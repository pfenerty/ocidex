{{/*
Expand the name of the chart.
*/}}
{{- define "ocidex.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ocidex.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ocidex.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "ocidex.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: {{ include "ocidex.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for a given component.
Usage: {{ include "ocidex.selectorLabels" (dict "root" . "component" "api") }}
*/}}
{{- define "ocidex.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ocidex.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Pod template labels: selector labels + Hubble-visible metadata.
Usage: {{ include "ocidex.podLabels" (dict "root" . "component" "api") }}
*/}}
{{- define "ocidex.podLabels" -}}
{{- include "ocidex.selectorLabels" . }}
app.kubernetes.io/part-of: {{ include "ocidex.name" .root }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
{{- end }}

{{/*
Resolve image tag: use .Values.image.tag if set, otherwise fall back to Chart.AppVersion.
Usage: {{ include "ocidex.imageTag" . }}
*/}}
{{- define "ocidex.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Full image reference for a named component.
Usage: {{ include "ocidex.image" (dict "root" . "name" "api") }}
*/}}
{{- define "ocidex.image" -}}
{{ .root.Values.image.registry }}/ocidex-{{ .name }}:{{ include "ocidex.imageTag" .root }}
{{- end }}
