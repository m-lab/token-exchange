package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AutojoinRequestsTotal counts incoming autojoin token requests.
	// Used with promhttp.InstrumentHandlerCounter.
	AutojoinRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tokenexchange_autojoin_requests_total",
			Help: "Total number of autojoin token requests.",
		},
		[]string{"code", "method"},
	)

	// AutojoinRequestDuration measures autojoin token request latency.
	// Used with promhttp.InstrumentHandlerDuration.
	AutojoinRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tokenexchange_autojoin_request_duration_seconds",
			Help:    "Duration of autojoin token requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code", "method"},
	)

	// IntegrationRequestsTotal counts incoming integration token requests.
	// Used with promhttp.InstrumentHandlerCounter.
	IntegrationRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tokenexchange_integration_requests_total",
			Help: "Total number of integration token requests.",
		},
		[]string{"code", "method"},
	)

	// IntegrationRequestDuration measures integration token request latency.
	// Used with promhttp.InstrumentHandlerDuration.
	IntegrationRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tokenexchange_integration_request_duration_seconds",
			Help:    "Duration of integration token requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code", "method"},
	)
)
