{{/*
SENTINEL APEX — Helm Template Helpers
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "sentinel-apex.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sentinel-apex.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "sentinel-apex.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sentinel-apex.labels" -}}
helm.sh/chart: {{ include "sentinel-apex.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: sentinel-apex
environment: {{ .Values.global.environment }}
{{- end }}

{{/*
Selector labels for a component
Usage: {{ include "sentinel-apex.selectorLabels" (dict "component" "api-gateway" "root" .) }}
*/}}
{{- define "sentinel-apex.selectorLabels" -}}
app.kubernetes.io/name: sentinel-apex
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{/*
Image reference helper
Usage: {{ include "sentinel-apex.image" (dict "image" .Values.apiGateway.image "root" .) }}
*/}}
{{- define "sentinel-apex.image" -}}
{{- $registry := .root.Values.global.imageRegistry -}}
{{- $tag := .image.tag | default .root.Values.global.imageTag -}}
{{- printf "%s/%s:%s" $registry .image.repository $tag -}}
{{- end }}

{{/*
Standard security context (restricted pod security standard)
*/}}
{{- define "sentinel-apex.securityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Standard container security context
*/}}
{{- define "sentinel-apex.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 1000
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Standard affinity for a component
*/}}
{{- define "sentinel-apex.affinity" -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchLabels:
            app.kubernetes.io/component: {{ .component }}
        topologyKey: kubernetes.io/hostname
{{- end }}

{{/*
ServiceAccount name for a component
*/}}
{{- define "sentinel-apex.serviceAccountName" -}}
{{ include "sentinel-apex.fullname" .root }}-{{ .component }}
{{- end }}
