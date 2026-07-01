{{/*
Common labels
*/}}
{{- define "observability-example.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Tempo endpoint for the collector exporter
*/}}
{{- define "observability-example.tempoEndpoint" -}}
{{- if .Values.collector.tempoEndpoint -}}
{{ .Values.collector.tempoEndpoint }}
{{- else -}}
tempo.{{ .Release.Namespace }}.svc.cluster.local:4317
{{- end -}}
{{- end }}
