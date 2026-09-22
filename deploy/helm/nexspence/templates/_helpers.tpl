{{/*
Expand the name of the chart.
*/}}
{{- define "nexspence.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nexspence.fullname" -}}
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
{{- define "nexspence.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "nexspence.labels" -}}
helm.sh/chart: {{ include "nexspence.chart" . }}
{{ include "nexspence.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "nexspence.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nexspence.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "nexspence.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nexspence.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL DSN — bundled (own StatefulSet, postgres-statefulset.yaml) or external.
*/}}
{{- define "nexspence.databaseDSN" -}}
{{- if eq .Values.database.mode "bundled" }}
{{- printf "postgres://%s:%s@%s-postgres:5432/%s?sslmode=disable"
    .Values.database.bundled.auth.username
    .Values.database.bundled.auth.password
    (include "nexspence.fullname" .)
    .Values.database.bundled.auth.database }}
{{- else }}
{{- .Values.database.external.dsn }}
{{- end }}
{{- end }}

{{- define "nexspence.redisAddr" -}}
{{- if eq .Values.redis.mode "bundled" }}
{{- printf "%s-redis-master:6379" .Release.Name }}
{{- else }}
{{- .Values.redis.addr }}
{{- end }}
{{- end }}

{{- define "nexspence.redisPassword" -}}
{{- .Values.redis.auth.password }}
{{- end }}

{{- define "nexspence.redisDB" -}}
{{- if eq .Values.redis.mode "bundled" }}
{{- 0 }}
{{- else }}
{{- .Values.redis.db }}
{{- end }}
{{- end }}

{{/*
Whether the mounted /app/config.yaml file is needed at all: a YAML map
(subdomain-connector aliases, any *.role_mappings) cannot be expressed as an
environment variable, so it rides in this file instead. Shared between
configmap.yaml (renders the file) and deployment.yaml (mounts it) so both stay
in sync on what triggers it.
*/}}
{{- define "nexspence.needsConfigFile" -}}
{{- if or .Values.config.docker.subdomainConnector.aliases .Values.oidc.roleMappings .Values.ldap.roleMappings .Values.saml.roleMappings -}}
true
{{- end -}}
{{- end }}

{{/*
The port the server actually listens on, taken from config.httpAddr
(":8081", "0.0.0.0:8081"). The containerPort, both probes and the Service
read it from here, so changing httpAddr moves all of them together instead
of leaving the pod pointing at a port nothing serves.
*/}}
{{- define "nexspence.httpPort" -}}
{{- $listen := default ":8081" .Values.config.httpAddr -}}
{{- $port := last (splitList ":" $listen) -}}
{{- if not (regexMatch "^[0-9]+$" $port) -}}
{{- fail (printf "config.httpAddr %q has no port; expected something like \":8081\"" $listen) -}}
{{- end -}}
{{- $port -}}
{{- end }}
