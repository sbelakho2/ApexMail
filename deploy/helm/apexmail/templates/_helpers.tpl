{{/*
ApexMail Helm Chart — Template Helpers
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "apexmail.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "apexmail.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "apexmail.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "apexmail.labels" -}}
helm.sh/chart: {{ include "apexmail.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: apexmail
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels for a specific component.
Usage: {{ include "apexmail.selectorLabels" (dict "name" "api-server" "context" .) }}
*/}}
{{- define "apexmail.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- end }}

{{/*
Full image reference for a component.
Usage: {{ include "apexmail.image" (dict "image" .Values.apiServer.image "global" .Values.global "chart" .Chart) }}
*/}}
{{- define "apexmail.image" -}}
{{- $registry := .global.imageRegistry -}}
{{- $repository := .image.repository -}}
{{- $tag := .image.tag | default .chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "apexmail.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "apexmail.fullname" . }}
{{- end }}
{{- end }}

{{/*
Image pull secrets.
*/}}
{{- define "apexmail.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Pod security context (shared across all workloads).
*/}}
{{- define "apexmail.podSecurityContext" -}}
securityContext:
  runAsNonRoot: {{ .Values.podSecurityContext.runAsNonRoot }}
  runAsUser: {{ .Values.podSecurityContext.runAsUser }}
  runAsGroup: {{ .Values.podSecurityContext.runAsGroup }}
  fsGroup: {{ .Values.podSecurityContext.fsGroup }}
  seccompProfile:
    type: RuntimeDefault
{{- end }}

{{/*
Container security context (shared across all workloads).
*/}}
{{- define "apexmail.containerSecurityContext" -}}
securityContext:
  allowPrivilegeEscalation: {{ .Values.containerSecurityContext.allowPrivilegeEscalation }}
  readOnlyRootFilesystem: {{ .Values.containerSecurityContext.readOnlyRootFilesystem }}
  capabilities:
    drop:
    {{- range .Values.containerSecurityContext.capabilities.drop }}
      - {{ . }}
    {{- end }}
{{- end }}

{{/*
Database URL — resolves to either in-cluster PostgreSQL or external.
*/}}
{{- define "apexmail.databaseHost" -}}
{{- if .Values.postgresql.enabled -}}
{{ include "apexmail.fullname" . }}-postgresql
{{- else -}}
{{ .Values.externalDatabase.host }}
{{- end -}}
{{- end }}

{{- define "apexmail.databasePort" -}}
{{- if .Values.postgresql.enabled -}}
5432
{{- else -}}
{{ .Values.externalDatabase.port }}
{{- end -}}
{{- end }}

{{/*
Redis host — resolves to either in-cluster Redis or external.
*/}}
{{- define "apexmail.redisHost" -}}
{{- if .Values.redis.enabled -}}
{{ include "apexmail.fullname" . }}-redis-master
{{- else -}}
{{ .Values.externalRedis.host }}
{{- end -}}
{{- end }}

{{- define "apexmail.redisPort" -}}
{{- if .Values.redis.enabled -}}
6379
{{- else -}}
{{ .Values.externalRedis.port }}
{{- end -}}
{{- end }}

{{/*
Topology spread constraints.
*/}}
{{- define "apexmail.topologySpreadConstraints" -}}
{{- if .Values.topologySpreadConstraints }}
topologySpreadConstraints:
{{- range .Values.topologySpreadConstraints }}
  - maxSkew: {{ .maxSkew }}
    topologyKey: {{ .topologyKey }}
    whenUnsatisfiable: {{ .whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "apexmail.selectorLabels" (dict "name" $.componentName "context" $.context) | nindent 8 }}
{{- end }}
{{- end }}
{{- end }}
