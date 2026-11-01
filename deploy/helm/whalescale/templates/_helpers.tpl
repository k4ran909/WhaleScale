{{- define "whalescale.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "whalescale.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "whalescale.labels" -}}
{{ include "whalescale.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* The host part of publicURL. */}}
{{- define "whalescale.publicHost" -}}
{{- required "publicURL is required, e.g. --set publicURL=https://ws.example.com" .Values.publicURL | regexReplaceAll "^[a-zA-Z]+://([^/:]+).*$" "${1}" -}}
{{- end -}}

{{- define "whalescale.dbSecret" -}}
{{- if .Values.database.existingSecret -}}{{ .Values.database.existingSecret }}{{- else -}}{{ include "whalescale.fullname" . }}-db{{- end -}}
{{- end -}}

{{- define "whalescale.oidcSecret" -}}
{{- if .Values.oidc.existingSecret -}}{{ .Values.oidc.existingSecret }}{{- else -}}{{ include "whalescale.fullname" . }}-oidc{{- end -}}
{{- end -}}

{{- define "whalescale.usesPostgres" -}}
{{- if or .Values.database.url .Values.database.existingSecret -}}true{{- end -}}
{{- end -}}
