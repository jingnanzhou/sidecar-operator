{{- define "sidecar-operator.ns" -}}
{{- default .Release.Namespace .Values.global.nsOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
