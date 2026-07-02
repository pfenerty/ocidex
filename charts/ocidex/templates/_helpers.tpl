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
Precedence: explicit .Values.image.tag > per-component .Values.image.digests.<name> >
Chart.AppVersion. The digest form (populated at release-package time) pins releases to an
immutable ...@sha256:... ref; an explicit tag still wins so dev can override with :main.
Usage: {{ include "ocidex.image" (dict "root" . "name" "api") }}
*/}}
{{- define "ocidex.image" -}}
{{- $base := printf "ocidex-%s" .name -}}
{{- if .root.Values.image.registry -}}
{{- $base = printf "%s/%s" .root.Values.image.registry $base -}}
{{- end -}}
{{- $digest := "" -}}
{{- if .root.Values.image.digests -}}
{{- $digest = index .root.Values.image.digests .name -}}
{{- end -}}
{{- if .root.Values.image.tag -}}
{{ $base }}:{{ .root.Values.image.tag }}
{{- else if $digest -}}
{{ $base }}@{{ $digest }}
{{- else -}}
{{ $base }}:{{ .root.Chart.AppVersion }}
{{- end -}}
{{- end }}
