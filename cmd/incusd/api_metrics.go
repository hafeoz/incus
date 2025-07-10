package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lxc/incus/v6/internal/server/auth"
	"github.com/lxc/incus/v6/internal/server/db"
	dbCluster "github.com/lxc/incus/v6/internal/server/db/cluster"
	"github.com/lxc/incus/v6/internal/server/instance"
	instanceDrivers "github.com/lxc/incus/v6/internal/server/instance/drivers"
	"github.com/lxc/incus/v6/internal/server/locking"
	"github.com/lxc/incus/v6/internal/server/metrics"
	"github.com/lxc/incus/v6/internal/server/request"
	"github.com/lxc/incus/v6/internal/server/response"
	"github.com/lxc/incus/v6/internal/server/state"
	internalutil "github.com/lxc/incus/v6/internal/util"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/logger"
)

type metricsCacheEntry struct {
	metrics *metrics.MetricSet
	expiry  time.Time
}

var (
	metricsCache     map[string]metricsCacheEntry
	metricsCacheLock sync.Mutex
)

var metricsCmd = APIEndpoint{
	Path: "metrics",

	Get: APIEndpointAction{Handler: metricsGet, AccessHandler: allowMetrics, AllowUntrusted: true},
}

func allowMetrics(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	if !s.GlobalConfig.MetricsAuthentication() {
		return response.EmptySyncResponse
	}

	return allowPermission(auth.ObjectTypeServer, auth.EntitlementCanViewMetrics)(d, r)
}

// swagger:operation GET /1.0/metrics metrics metrics_get
//
//	Get metrics
//
//	Gets metrics of instances.
//
//	---
//	produces:
//	  - text/plain
//	parameters:
//	  - in: query
//	    name: project
//	    description: Project name
//	    type: string
//	    example: default
//	  - in: query
//	    name: target
//	    description: Cluster member name
//	    type: string
//	    example: server01
//	responses:
//	  "200":
//	    description: Metrics
//	    schema:
//	      type: string
//	      description: Instance metrics
//	  "403":
//	    $ref: "#/responses/Forbidden"
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func metricsGet(d *Daemon, r *http.Request) response.Response {
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	logger.Info("DEBUG: metricsGet started", logger.Ctx{"requestID": requestID})
	
	s := d.State()

	projectName := request.QueryParam(r, "project")
	compress := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")

	// Forward if requested.
	resp := forwardedResponseIfTargetIsRemote(s, r)
	if resp != nil {
		logger.Info("DEBUG: forwarding request", logger.Ctx{"requestID": requestID})
		return resp
	}

	// Wait until daemon is fully started.
	logger.Info("DEBUG: waiting for daemon ready", logger.Ctx{"requestID": requestID})
	<-d.waitReady.Done()
	logger.Info("DEBUG: daemon ready completed", logger.Ctx{"requestID": requestID})

	// Prepare response.
	metricSet := metrics.NewMetricSet(nil)

	var projectNames []string

	logger.Info("DEBUG: starting initial database transaction", logger.Ctx{"requestID": requestID})
	err := s.DB.Cluster.Transaction(r.Context(), func(ctx context.Context, tx *db.ClusterTx) error {
		logger.Info("DEBUG: inside initial database transaction", logger.Ctx{"requestID": requestID})
		
		// Figure out the projects to retrieve.
		if projectName != "" {
			projectNames = []string{projectName}
		} else {
			// Get all project names if no specific project requested.
			logger.Info("DEBUG: getting all projects", logger.Ctx{"requestID": requestID})
			projects, err := dbCluster.GetProjects(ctx, tx.Tx())
			if err != nil {
				logger.Error("DEBUG: failed to get projects", logger.Ctx{"requestID": requestID, "err": err})
				return fmt.Errorf("Failed loading projects: %w", err)
			}

			projectNames = make([]string, 0, len(projects))
			for _, project := range projects {
				projectNames = append(projectNames, project.Name)
			}
			logger.Info("DEBUG: got projects", logger.Ctx{"requestID": requestID, "count": len(projectNames)})
		}

		// Add internal metrics.
		logger.Info("DEBUG: adding internal metrics", logger.Ctx{"requestID": requestID})
		metricSet.Merge(internalMetrics(ctx, s.StartTime, tx))
		logger.Info("DEBUG: internal metrics added", logger.Ctx{"requestID": requestID})

		return nil
	})
	if err != nil {
		logger.Error("DEBUG: initial database transaction failed", logger.Ctx{"requestID": requestID, "err": err})
		return response.SmartError(err)
	}
	logger.Info("DEBUG: initial database transaction completed", logger.Ctx{"requestID": requestID})

	// invalidProjectFilters returns project filters which are either not in cache or have expired.
	invalidProjectFilters := func(projectNames []string) []dbCluster.InstanceFilter {
		logger.Info("DEBUG: checking cache validity", logger.Ctx{"requestID": requestID, "projects": len(projectNames)})
		metricsCacheLock.Lock()
		defer metricsCacheLock.Unlock()

		var filters []dbCluster.InstanceFilter
		for _, p := range projectNames {
			projectName := p // Local var for filter pointer.

			cache, ok := metricsCache[projectName]
			if !ok || cache.expiry.Before(time.Now()) {
				// If missing or expired, record it.
				filters = append(filters, dbCluster.InstanceFilter{
					Project: &projectName,
					Node:    &s.ServerName,
				})

				continue
			}

			// If present and valid, merge the existing data.
			metricSet.Merge(cache.metrics)
		}

		logger.Info("DEBUG: cache check completed", logger.Ctx{"requestID": requestID, "invalid": len(filters), "total": len(projectNames)})
		return filters
	}

	// Review the cache for invalid projects.
	projectsToFetch := invalidProjectFilters(projectNames)

	// If all valid, return immediately.
	if len(projectsToFetch) == 0 {
		logger.Info("DEBUG: all metrics cached, returning immediately", logger.Ctx{"requestID": requestID})
		return getFilteredMetrics(s, r, compress, metricSet)
	}

	cacheDuration := time.Duration(8) * time.Second

	// Acquire update lock.
	logger.Info("DEBUG: attempting to acquire metricsGet lock", logger.Ctx{"requestID": requestID, "timeout": cacheDuration.String()})
	lockCtx, lockCtxCancel := context.WithTimeout(r.Context(), cacheDuration)
	defer lockCtxCancel()

	unlock, err := locking.Lock(lockCtx, "metricsGet")
	if err != nil {
		logger.Error("DEBUG: failed to acquire metricsGet lock", logger.Ctx{"requestID": requestID, "err": err})
		return response.SmartError(api.StatusErrorf(http.StatusLocked, "Metrics are currently being built by another request: %s", err))
	}
	logger.Info("DEBUG: successfully acquired metricsGet lock", logger.Ctx{"requestID": requestID})

	defer func() {
		logger.Info("DEBUG: releasing metricsGet lock", logger.Ctx{"requestID": requestID})
		unlock()
		logger.Info("DEBUG: metricsGet lock released", logger.Ctx{"requestID": requestID})
	}()

	// Setup a new response.
	metricSet = metrics.NewMetricSet(nil)

	// Check if any of the missing data has been filled in since acquiring the lock.
	// As its possible another request was already populating the cache when we tried to take the lock.
	logger.Info("DEBUG: re-checking cache after acquiring lock", logger.Ctx{"requestID": requestID})
	projectsToFetch = invalidProjectFilters(projectNames)

	// If all valid, return immediately.
	if len(projectsToFetch) == 0 {
		logger.Info("DEBUG: all metrics now cached after lock acquisition, returning", logger.Ctx{"requestID": requestID})
		return getFilteredMetrics(s, r, compress, metricSet)
	}

	// Gather information about host interfaces once.
	logger.Info("DEBUG: gathering host interfaces", logger.Ctx{"requestID": requestID})
	hostInterfaces, _ := net.Interfaces()
	logger.Info("DEBUG: host interfaces gathered", logger.Ctx{"requestID": requestID, "count": len(hostInterfaces)})

	var instances []instance.Instance
	logger.Info("DEBUG: starting instance list transaction", logger.Ctx{"requestID": requestID, "projectsToFetch": len(projectsToFetch)})
	err = s.DB.Cluster.Transaction(r.Context(), func(ctx context.Context, tx *db.ClusterTx) error {
		logger.Info("DEBUG: inside instance list transaction", logger.Ctx{"requestID": requestID})
		return tx.InstanceList(ctx, func(dbInst db.InstanceArgs, p api.Project) error {
			logger.Info("DEBUG: loading instance", logger.Ctx{"requestID": requestID, "instance": dbInst.Name, "project": dbInst.Project})
			inst, err := instance.Load(s, dbInst, p)
			if err != nil {
				logger.Error("DEBUG: failed to load instance", logger.Ctx{"requestID": requestID, "instance": dbInst.Name, "project": dbInst.Project, "err": err})
				return fmt.Errorf("Failed loading instance %q in project %q: %w", dbInst.Name, dbInst.Project, err)
			}

			instances = append(instances, inst)
			logger.Info("DEBUG: instance loaded successfully", logger.Ctx{"requestID": requestID, "instance": dbInst.Name, "project": dbInst.Project})

			return nil
		}, projectsToFetch...)
	})
	if err != nil {
		logger.Error("DEBUG: instance list transaction failed", logger.Ctx{"requestID": requestID, "err": err})
		return response.SmartError(err)
	}
	logger.Info("DEBUG: instance list transaction completed", logger.Ctx{"requestID": requestID, "instanceCount": len(instances)})

	// Prepare temporary metrics storage.
	newMetrics := make(map[string]*metrics.MetricSet, len(projectsToFetch))
	newMetricsLock := sync.Mutex{}

	// Limit metrics build concurrency to number of instances or number of CPU cores (which ever is less).
	var wg sync.WaitGroup
	instMetricsCh := make(chan instance.Instance)
	maxConcurrent := runtime.NumCPU()
	instCount := len(instances)
	if instCount < maxConcurrent {
		maxConcurrent = instCount
	}

	logger.Info("DEBUG: starting metrics collection", logger.Ctx{"requestID": requestID, "instanceCount": instCount, "maxConcurrent": maxConcurrent})

	// Start metrics builder routines.
	for i := range maxConcurrent {
		go func(workerID int, instMetricsCh <-chan instance.Instance) {
			logger.Info("DEBUG: metrics worker started", logger.Ctx{"requestID": requestID, "workerID": workerID})
			for inst := range instMetricsCh {
				logger.Info("DEBUG: processing instance metrics", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": inst.Project().Name})
				projectName := inst.Project().Name
				instanceMetrics, err := inst.Metrics(hostInterfaces)
				if err != nil {
					// Ignore stopped instances.
					if !errors.Is(err, instanceDrivers.ErrInstanceIsStopped) {
						logger.Warn("Failed getting instance metrics", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": projectName, "err": err})
					} else {
						logger.Info("DEBUG: instance stopped, skipping metrics", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": projectName})
					}
				} else {
					// Add the metrics.
					logger.Info("DEBUG: adding instance metrics to cache", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": projectName})
					newMetricsLock.Lock()

					// Initialize metrics set for project if needed.
					if newMetrics[projectName] == nil {
						newMetrics[projectName] = metrics.NewMetricSet(nil)
					}

					newMetrics[projectName].Merge(instanceMetrics)

					newMetricsLock.Unlock()
					logger.Info("DEBUG: instance metrics added successfully", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": projectName})
				}

				logger.Info("DEBUG: instance processing completed", logger.Ctx{"requestID": requestID, "workerID": workerID, "instance": inst.Name(), "project": inst.Project().Name})
				wg.Done()
			}
			logger.Info("DEBUG: metrics worker finished", logger.Ctx{"requestID": requestID, "workerID": workerID})
		}(i, instMetricsCh)
	}

	// Fetch what's missing.
	logger.Info("DEBUG: queuing instances for metrics collection", logger.Ctx{"requestID": requestID, "instanceCount": len(instances)})
	for _, inst := range instances {
		logger.Info("DEBUG: queuing instance", logger.Ctx{"requestID": requestID, "instance": inst.Name(), "project": inst.Project().Name})
		wg.Add(1)
		instMetricsCh <- inst
	}
	logger.Info("DEBUG: all instances queued", logger.Ctx{"requestID": requestID})

	logger.Info("DEBUG: waiting for all workers to complete", logger.Ctx{"requestID": requestID})
	wg.Wait()
	logger.Info("DEBUG: all workers completed", logger.Ctx{"requestID": requestID})
	
	close(instMetricsCh)
	logger.Info("DEBUG: metrics channel closed", logger.Ctx{"requestID": requestID})

	// Put the new data in the global cache and in response.
	logger.Info("DEBUG: updating global cache", logger.Ctx{"requestID": requestID})
	metricsCacheLock.Lock()

	if metricsCache == nil {
		metricsCache = map[string]metricsCacheEntry{}
	}

	updatedProjects := []string{}
	for project, entries := range newMetrics {
		logger.Info("DEBUG: caching project metrics", logger.Ctx{"requestID": requestID, "project": project})
		metricsCache[project] = metricsCacheEntry{
			expiry:  time.Now().Add(cacheDuration),
			metrics: entries,
		}

		updatedProjects = append(updatedProjects, project)
		metricSet.Merge(entries)
	}

	for _, project := range projectsToFetch {
		if slices.Contains(updatedProjects, *project.Project) {
			continue
		}

		logger.Info("DEBUG: caching empty project metrics", logger.Ctx{"requestID": requestID, "project": *project.Project})
		metricsCache[*project.Project] = metricsCacheEntry{
			expiry: time.Now().Add(cacheDuration),
		}
	}

	metricsCacheLock.Unlock()
	logger.Info("DEBUG: global cache updated", logger.Ctx{"requestID": requestID})

	logger.Info("DEBUG: metricsGet completed successfully", logger.Ctx{"requestID": requestID})
	return getFilteredMetrics(s, r, compress, metricSet)
}

func getFilteredMetrics(s *state.State, r *http.Request, compress bool, metricSet *metrics.MetricSet) response.Response {
	if !s.GlobalConfig.MetricsAuthentication() {
		return response.SyncResponsePlain(true, compress, metricSet.String())
	}

	// Get instances the user is allowed to view.
	userHasPermission, err := s.Authorizer.GetPermissionChecker(r.Context(), r, auth.EntitlementCanView, auth.ObjectTypeInstance)
	if err != nil && !api.StatusErrorCheck(err, http.StatusForbidden) {
		return response.SmartError(err)
	} else if err != nil {
		userHasPermission, err = s.Authorizer.GetPermissionChecker(r.Context(), r, auth.EntitlementCanViewMetrics, auth.ObjectTypeInstance)
		if err != nil {
			return response.SmartError(err)
		}
	}

	metricSet.FilterSamples(userHasPermission)

	return response.SyncResponsePlain(true, compress, metricSet.String())
}

func internalMetrics(ctx context.Context, daemonStartTime time.Time, tx *db.ClusterTx) *metrics.MetricSet {
	out := metrics.NewMetricSet(nil)

	warnings, err := dbCluster.GetWarnings(ctx, tx.Tx())
	if err != nil {
		logger.Warn("Failed to get warnings", logger.Ctx{"err": err})
	} else {
		// Total number of warnings
		out.AddSamples(metrics.WarningsTotal, metrics.Sample{Value: float64(len(warnings))})
	}

	operations, err := dbCluster.GetOperations(ctx, tx.Tx())
	if err != nil {
		logger.Warn("Failed to get operations", logger.Ctx{"err": err})
	} else {
		// Total number of operations
		out.AddSamples(metrics.OperationsTotal, metrics.Sample{Value: float64(len(operations))})
	}

	// Daemon uptime
	out.AddSamples(metrics.UptimeSeconds, metrics.Sample{Value: time.Since(daemonStartTime).Seconds()})

	// Number of goroutines
	out.AddSamples(metrics.GoGoroutines, metrics.Sample{Value: float64(runtime.NumGoroutine())})

	// Go memory stats
	var ms runtime.MemStats

	runtime.ReadMemStats(&ms)

	out.AddSamples(metrics.GoAllocBytes, metrics.Sample{Value: float64(ms.Alloc)})
	out.AddSamples(metrics.GoAllocBytesTotal, metrics.Sample{Value: float64(ms.TotalAlloc)})
	out.AddSamples(metrics.GoBuckHashSysBytes, metrics.Sample{Value: float64(ms.BuckHashSys)})
	out.AddSamples(metrics.GoFreesTotal, metrics.Sample{Value: float64(ms.Frees)})
	out.AddSamples(metrics.GoGCSysBytes, metrics.Sample{Value: float64(ms.GCSys)})
	out.AddSamples(metrics.GoHeapAllocBytes, metrics.Sample{Value: float64(ms.HeapAlloc)})
	out.AddSamples(metrics.GoHeapIdleBytes, metrics.Sample{Value: float64(ms.HeapIdle)})
	out.AddSamples(metrics.GoHeapInuseBytes, metrics.Sample{Value: float64(ms.HeapInuse)})
	out.AddSamples(metrics.GoHeapObjects, metrics.Sample{Value: float64(ms.HeapObjects)})
	out.AddSamples(metrics.GoHeapReleasedBytes, metrics.Sample{Value: float64(ms.HeapReleased)})
	out.AddSamples(metrics.GoHeapSysBytes, metrics.Sample{Value: float64(ms.HeapSys)})
	out.AddSamples(metrics.GoLookupsTotal, metrics.Sample{Value: float64(ms.Lookups)})
	out.AddSamples(metrics.GoMallocsTotal, metrics.Sample{Value: float64(ms.Mallocs)})
	out.AddSamples(metrics.GoMCacheInuseBytes, metrics.Sample{Value: float64(ms.MCacheInuse)})
	out.AddSamples(metrics.GoMCacheSysBytes, metrics.Sample{Value: float64(ms.MCacheSys)})
	out.AddSamples(metrics.GoMSpanInuseBytes, metrics.Sample{Value: float64(ms.MSpanInuse)})
	out.AddSamples(metrics.GoMSpanSysBytes, metrics.Sample{Value: float64(ms.MSpanSys)})
	out.AddSamples(metrics.GoNextGCBytes, metrics.Sample{Value: float64(ms.NextGC)})
	out.AddSamples(metrics.GoOtherSysBytes, metrics.Sample{Value: float64(ms.OtherSys)})
	out.AddSamples(metrics.GoStackInuseBytes, metrics.Sample{Value: float64(ms.StackInuse)})
	out.AddSamples(metrics.GoStackSysBytes, metrics.Sample{Value: float64(ms.StackSys)})
	out.AddSamples(metrics.GoSysBytes, metrics.Sample{Value: float64(ms.Sys)})

	// If on Incus OS, include OS metrics.
	if internalutil.IsIncusOS() {
		client := http.Client{}
		client.Transport = &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", "127.0.0.1:9100", 50*time.Millisecond)
			},
			DisableKeepAlives:     true,
			ExpectContinueTimeout: time.Second * 3,
			ResponseHeaderTimeout: time.Second * 3,
		}

		resp, err := client.Get("http://incus-os/metrics")
		if err == nil {
			defer resp.Body.Close()

			osMetrics, err := io.ReadAll(resp.Body)
			if err == nil {
				out.AddRaw(osMetrics)
			}
		}
	}

	return out
}
