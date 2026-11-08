/**
 * API documentation, spec and diagnostic endpoints, as conventional locations.
 *
 * Same contract as the rest of the exposure sweep: one plain GET of a path the
 * framework itself documents, a status code, a content signature, and nothing
 * else. No endpoint is guessed at, no parameter is fuzzed, no introspection
 * query is sent, and nothing a path returns is read beyond the first 16 KB
 * needed to tell a real spec from the site's 404 page.
 *
 * Severity here is about what the endpoint discloses, not about whether it is
 * exploitable. A published OpenAPI spec is a legitimate choice for a public
 * API and a serious leak for an internal one, so the findings describe the
 * disclosure and leave that judgement to the reader. `/actuator/env` is the
 * exception: it returns configuration and environment variables, and there is
 * no reading of that which is fine.
 */

import type { ExposurePath } from './exposure-paths';

export const API_PATHS: ExposurePath[] = [
  {
    path: '/swagger.json',
    description:
      'OpenAPI/Swagger specification — documents every endpoint, parameter and schema the API accepts',
    severity: 'medium',
    signatures: [/"(?:swagger|openapi)"\s*:\s*"/i, /"paths"\s*:\s*\{/],
    recommendation:
      'If the API is not meant to be public, serve the spec only to authenticated users or ship it with the client instead. If it is public, review it for internal-only endpoints that were never meant to be listed.',
  },
  {
    path: '/openapi.json',
    description: 'OpenAPI specification — a full machine-readable map of the API',
    severity: 'medium',
    signatures: [/"openapi"\s*:\s*"3/i, /"paths"\s*:\s*\{/],
    recommendation:
      'Restrict the spec to authenticated callers, or confirm every endpoint it lists is intended to be public.',
  },
  {
    path: '/api-docs',
    description: 'Swagger UI — an interactive console for calling the API',
    severity: 'medium',
    signatures: [/swagger-ui/i, /"(?:swagger|openapi)"\s*:/i, /redoc/i],
    recommendation:
      'Disable the docs UI in production, or put it behind authentication. An interactive console removes every obstacle between a visitor and your API.',
  },
  {
    path: '/v2/api-docs',
    description: 'Springfox/Swagger 2 spec — the default docs path on Spring Boot',
    severity: 'medium',
    signatures: [/"swagger"\s*:\s*"2/i, /"paths"\s*:\s*\{/],
    recommendation: 'Set springfox/springdoc to disabled in the production profile.',
  },
  {
    path: '/graphql',
    description: 'GraphQL endpoint',
    severity: 'low',
    // A GET with no query is the ordinary way to see whether the endpoint is
    // there; every server below answers with an error that names itself. No
    // introspection query is sent.
    signatures: [
      /must provide (?:a )?query/i,
      /GET (?:query|requests?) /i,
      /"errors"\s*:\s*\[/,
      /graphql-playground|graphiql|apollo/i,
    ],
    recommendation:
      'Confirm introspection and the playground UI are disabled in production, that queries are depth- and cost-limited, and that field-level authorisation does not rely on the client choosing not to ask.',
  },
  {
    path: '/actuator/env',
    description:
      'Spring Boot Actuator environment — configuration properties and environment variables, typically including credentials',
    severity: 'critical',
    signatures: [/"(?:propertySources|activeProfiles)"/i, /"systemEnvironment"/i],
    recommendation:
      'Restrict the actuator endpoints to a management port that is not publicly routable, expose only /health, and rotate every credential the endpoint returns — assume it has been read.',
  },
  {
    path: '/metrics',
    description:
      'Prometheus metrics — internal hostnames, route names, dependency versions and traffic volumes',
    severity: 'medium',
    signatures: [/^#\s*(?:HELP|TYPE)\s+\w+/m, /\bprocess_cpu_seconds_total\b/],
    recommendation:
      'Bind the metrics endpoint to an internal interface or require authentication. Metrics names map out your internal architecture and its load.',
  },
  {
    path: '/wp-json/wp/v2/users',
    description: 'WordPress REST API user list — enumerates account usernames',
    severity: 'low',
    // Matched on the response shape only. The scanner does not record or
    // report the usernames it would have to read to count them.
    signatures: [/"slug"\s*:/, /"(?:id|name)"\s*:/],
    recommendation:
      'Restrict the users endpoint to authenticated requests. Published usernames turn a password-spray into a targeted one, and WordPress logins are already the most attacked surface on the web.',
  },
];
