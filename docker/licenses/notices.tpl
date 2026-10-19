{{ range . }}
================================================================================
{{ .Name }} {{ .Version }} ({{ .LicenseName }})
{{- if eq .LicenseName "MPL-2.0" }}
Source code form: https://pkg.go.dev/{{ .Name }}@{{ .Version }}
{{- end }}

{{ .LicenseText }}
{{- end }}
