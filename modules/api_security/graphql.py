#!/usr/bin/env python3
"""
GraphQL API Security Scanner Module.
Tests for common GraphQL security vulnerabilities.

References:
    - OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
    - Apollo GraphQL Security: https://www.apollographql.com/docs/apollo-server/security/
    - GraphQL Specification: https://spec.graphql.org/
"""

import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """GraphQL API security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize GraphQL scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "GraphQL Security Analysis"
        
        # Common GraphQL endpoint paths
        self.graphql_paths = [
            '/graphql',
            '/graphql/',
            '/api/graphql',
            '/api/graphql/',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/api',
            '/graphiql',
            '/graphql/console',
            '/playground',
            '/gql',
            '/gql/',
            '/api/gql',
            '/graphql/explorer',
            '/altair',
            '/voyager',
        ]
        
        # Introspection query
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        # Test queries for common vulnerabilities
        self.test_queries = {
            'user_enumeration': """
                query { users { id username email role } }
                query { user(id: 1) { id email password passwordHash } }
                query { admins { id username password } }
                query { accounts { id email token apiKey secretKey } }
            """,
            'sensitive_fields': """
                query { 
                  users { id email password passwordHash secretToken apiKey creditCard ssn }
                  __type(name: "User") { fields { name type { name } } }
                }
            """,
            'nested_queries': """
                query {
                  users {
                    id
                    posts {
                      id
                      comments {
                        id
                        author {
                          id
                          posts {
                            id
                            comments {
                              id
                              author {
                                id
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
            """,
        }
        
        # Mutation test payloads
        self.test_mutations = [
            """
            mutation { 
              createUser(input: {username: "test_hacker", email: "hacker@test.com", role: "admin", isAdmin: true}) { 
                id username role 
              } 
            }
            """,
            """
            mutation {
              updateUser(id: 1, input: {role: "admin", isAdmin: true}) {
                id username role
              }
            }
            """,
            """
            mutation {
              deleteUser(id: 1) { success }
            }
            """,
        ]
        
        # Error message patterns that indicate vulnerabilities
        self.error_patterns = [
            r'Cannot query field.*on type',
            r'Field.*doesn\'t exist on type',
            r'Variable.*of type.*was provided invalid value',
            r'Expected type.*, found',
            r'Not authorized',
            r'Unauthorized',
            r'Forbidden',
            r'Authentication required',
            r'Must be logged in',
            r'stacktrace',
            r'Traceback',
            r'at .*:\d+:\d+',
            r'GraphQL error',
        ]
    
    def run(self) -> Dict:
        """
        Execute GraphQL security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'graphql_detected': False,
            'graphql_endpoints': [],
            'active_endpoint': None,
            'introspection_enabled': False,
            'schema_exposed': False,
            'query_depth_limited': True,
            'rate_limited': True,
            'error_details_exposed': False,
            'sensitive_fields_found': [],
            'dangerous_mutations': [],
            'findings': []
        }
        
        # Stage 1: Discover GraphQL endpoints
        endpoints = self._discover_endpoints()
        result['graphql_endpoints'] = endpoints
        
        if endpoints:
            result['graphql_detected'] = True
            result['active_endpoint'] = endpoints[0]['url']
            active_url = endpoints[0]['url']
        else:
            result['findings'].append({
                'title': 'No GraphQL endpoint detected',
                'severity': 'info',
                'description': 'No GraphQL API endpoints were found on the target.',
                'recommendation': 'If GraphQL is in use, ensure it is properly secured.',
                'module': self.module_name,
            })
            return result
        
        # Stage 2: Test introspection
        introspection_result = self._test_introspection(active_url)
        result['introspection_enabled'] = introspection_result['enabled']
        result['schema_exposed'] = introspection_result['schema_retrieved']
        
        if introspection_result['enabled']:
            result['findings'].append({
                'title': 'GraphQL introspection is enabled',
                'severity': 'high',
                'description': (
                    "GraphQL introspection is enabled, allowing anyone to query the entire "
                    "API schema. This exposes all available types, fields, queries, mutations, "
                    "and their arguments. Attackers can use this information to discover "
                    "sensitive fields and craft targeted attacks."
                ),
                'recommendation': (
                    "1. Disable introspection in production environments\n"
                    "2. For Apollo Server: set 'introspection: false'\n"
                    "3. For GraphQL Yoga: use 'disableIntrospection' option\n"
                    "4. Consider using a query allowlist (persisted queries)\n"
                    "5. If introspection is needed, restrict it to authenticated admin users\n"
                    "6. Monitor GraphQL endpoint access patterns"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'evidence': 'Introspection query returned schema data',
                'references': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
                    'https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/',
                ]
            })
        
        # Stage 3: Test for sensitive field exposure
        sensitive_fields = self._check_sensitive_fields(active_url, introspection_result)
        if sensitive_fields:
            result['sensitive_fields_found'] = sensitive_fields
            result['findings'].append({
                'title': f'Sensitive fields exposed in GraphQL schema: {", ".join(sensitive_fields[:10])}',
                'severity': 'critical' if any(
                    f in sensitive_fields for f in ['password', 'token', 'secret', 'apikey']
                ) else 'high',
                'description': (
                    f"The GraphQL schema exposes potentially sensitive fields: "
                    f"{', '.join(sensitive_fields[:10])}. These fields may contain "
                    "passwords, tokens, or other confidential data accessible through queries."
                ),
                'recommendation': (
                    "1. Remove sensitive fields from the GraphQL schema\n"
                    "2. Use field-level authorization resolvers\n"
                    "3. Implement data masking for sensitive fields\n"
                    "4. Never expose passwords or secrets in the schema\n"
                    "5. Use DTOs (Data Transfer Objects) to control exposed data\n"
                    "6. Review and restrict field access based on user roles"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.0,
                'evidence': f"Sensitive fields: {sensitive_fields[:10]}",
            })
        
        # Stage 4: Test query depth limits (DoS protection)
        depth_result = self._test_query_depth(active_url)
        result['query_depth_limited'] = depth_result['limited']
        
        if not depth_result['limited']:
            result['findings'].append({
                'title': 'No query depth limiting detected',
                'severity': 'medium',
                'description': (
                    "The GraphQL API does not appear to limit query depth. This allows "
                    "attackers to send deeply nested queries that can cause denial of "
                    "service by exhausting server resources (CPU, memory, database connections)."
                ),
                'recommendation': (
                    "1. Implement query depth limiting (recommended max depth: 5-7)\n"
                    "2. Use 'graphql-depth-limit' package for Apollo Server\n"
                    "3. Set query complexity analysis with cost scoring\n"
                    "4. Implement rate limiting based on query complexity\n"
                    "5. Use persisted queries to prevent arbitrary queries\n"
                    "6. Set timeout limits for query execution"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-770',
                'cvss_score': 5.3,
                'evidence': 'Deeply nested query was accepted without restriction',
                'references': [
                    'https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a248ab3/',
                ]
            })
        
        # Stage 5: Test rate limiting
        rate_result = self._test_rate_limiting(active_url)
        result['rate_limited'] = rate_result['limited']
        
        if not rate_result['limited']:
            result['findings'].append({
                'title': 'No rate limiting on GraphQL endpoint',
                'severity': 'medium',
                'description': (
                    "The GraphQL endpoint does not appear to have rate limiting. "
                    "This makes it vulnerable to brute force attacks, data scraping, "
                    "and denial of service through excessive requests."
                ),
                'recommendation': (
                    "1. Implement rate limiting on the GraphQL endpoint\n"
                    "2. Use token bucket or sliding window algorithms\n"
                    "3. Consider different limits for authenticated vs unauthenticated users\n"
                    "4. Implement query cost analysis for dynamic rate limiting\n"
                    "5. Monitor for abnormal traffic patterns"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-770',
                'cvss_score': 5.3,
                'evidence': 'Multiple rapid requests accepted without throttling',
            })
        
        # Stage 6: Test error information disclosure
        error_result = self._test_error_disclosure(active_url)
        result['error_details_exposed'] = error_result['exposed']
        
        if error_result['exposed']:
            result['findings'].append({
                'title': 'GraphQL error messages reveal internal details',
                'severity': 'medium',
                'description': (
                    "GraphQL error responses contain detailed internal information such as "
                    "stack traces, database errors, or field type information. This helps "
                    "attackers understand the API structure and identify vulnerabilities."
                ),
                'recommendation': (
                    "1. Configure GraphQL to return generic error messages in production\n"
                    "2. Log detailed errors server-side only\n"
                    "3. Use error masking in Apollo Server: 'formatError'\n"
                    "4. Remove stack traces from error responses\n"
                    "5. Implement custom error handling middleware"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 4.0,
                'evidence': f"Error details: {error_result.get('sample', '')[:200]}",
            })
        
        # Stage 7: Test dangerous mutations
        if introspection_result['schema_retrieved']:
            dangerous = self._test_dangerous_mutations(active_url)
            if dangerous:
                result['dangerous_mutations'] = dangerous
                result['findings'].append({
                    'title': 'Potentially dangerous mutations accessible',
                    'severity': 'critical',
                    'description': (
                        f"GraphQL mutations that could modify user roles, delete data, or "
                        f"access sensitive operations were identified: {', '.join(dangerous[:5])}"
                    ),
                    'recommendation': (
                        "1. Implement strict authorization checks on all mutations\n"
                        "2. Use role-based access control (RBAC) for mutations\n"
                        "3. Validate input types and ranges strictly\n"
                        "4. Log all mutation operations for audit\n"
                        "5. Require additional authentication for sensitive mutations\n"
                        "6. Use allowlists for permitted mutation fields"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-862',
                    'cvss_score': 9.0,
                    'evidence': f"Dangerous mutations: {dangerous}",
                })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Endpoints: {len(endpoints)}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _discover_endpoints(self) -> List[Dict]:
        """
        Discover GraphQL endpoints on the target.
        
        Returns:
            List of discovered endpoint information
        """
        endpoints = []
        
        for path in self.graphql_paths:
            url = urljoin(self.target_url, path)
            
            # Try simple GET request
            resp = self.browser.get(path)
            if not resp:
                continue
            
            is_graphql = False
            
            # Check response for GraphQL indicators
            if resp.status_code in [200, 400, 405]:
                response_text = resp.text.lower()
                
                # Check for common GraphQL responses
                graphql_indicators = [
                    '"data"',
                    '"errors"',
                    '__schema',
                    '__type',
                    'graphql',
                    'query',
                    'mutation',
                    'introspection',
                ]
                
                for indicator in graphql_indicators:
                    if indicator in response_text:
                        is_graphql = True
                        break
                
                # Check Content-Type header
                content_type = resp.headers.get('Content-Type', '')
                if 'application/graphql' in content_type:
                    is_graphql = True
                if 'application/json' in content_type and resp.status_code == 200:
                    try:
                        data = json.loads(resp.text)
                        if isinstance(data, dict) and ('data' in data or 'errors' in data):
                            is_graphql = True
                    except:
                        pass
            
            if is_graphql:
                endpoints.append({
                    'url': url,
                    'path': path,
                    'status': resp.status_code,
                    'method': 'GET',
                })
        
        # Also try POST with GraphQL content type
        for path in self.graphql_paths[:5]:
            url = urljoin(self.target_url, path)
            
            try:
                test_query = json.dumps({'query': '{ __schema { queryType { name } } }'})
                headers = {'Content-Type': 'application/json'}
                
                resp = self.browser.post(path, data=test_query)
                
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.text)
                        if isinstance(data, dict) and 'data' in data:
                            if url not in [e['url'] for e in endpoints]:
                                endpoints.append({
                                    'url': url,
                                    'path': path,
                                    'status': resp.status_code,
                                    'method': 'POST',
                                })
                    except:
                        pass
            except:
                pass
        
        return endpoints
    
    def _test_introspection(self, graphql_url: str) -> Dict:
        """
        Test if GraphQL introspection is enabled.
        
        Args:
            graphql_url: GraphQL endpoint URL
        
        Returns:
            Dict with introspection test results
        """
        result = {
            'enabled': False,
            'schema_retrieved': False,
            'type_count': 0,
            'query_count': 0,
            'mutation_count': 0,
        }
        
        # Send introspection query
        payload = json.dumps({'query': self.introspection_query})
        
        resp = self.browser.post(
            graphql_url.replace(self.target_url, ''),
            data=payload
        )
        
        if not resp or resp.status_code != 200:
            return result
        
        try:
            data = json.loads(resp.text)
            
            if 'data' in data and '__schema' in data['data']:
                result['enabled'] = True
                schema = data['data']['__schema']
                
                if 'types' in schema:
                    result['type_count'] = len(schema['types'])
                    result['schema_retrieved'] = True
                
                if 'queryType' in schema and schema['queryType']:
                    result['query_count'] = 1
                
                if 'mutationType' in schema and schema['mutationType']:
                    result['mutation_count'] = 1
            
            # Check for partial schema exposure (errors but still some data)
            if 'errors' in data and 'data' in data:
                if data['data']:
                    result['enabled'] = True
                    result['schema_retrieved'] = True
            
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.debug(f"Introspection test error: {e}")
        
        return result
    
    def _check_sensitive_fields(self, graphql_url: str, introspection: Dict) -> List[str]:
        """
        Check for sensitive fields in GraphQL schema.
        
        Args:
            graphql_url: GraphQL endpoint URL
            introspection: Introspection test results
        
        Returns:
            List of sensitive field names found
        """
        if not introspection.get('schema_retrieved'):
            return []
        
        sensitive_keywords = [
            'password', 'passwd', 'pass', 'pwd',
            'token', 'secret', 'apikey', 'api_key',
            'creditcard', 'credit_card', 'cc', 'cvv',
            'ssn', 'socialsecurity', 'social_security',
            'pin', 'security_answer', 'security_question',
            'privatekey', 'private_key', 'secretkey',
            'accesstoken', 'access_token', 'refreshtoken',
            'authorization', 'auth', 'authenticate',
        ]
        
        found_fields = set()
        
        # Re-query schema for all types
        query = """
        query {
          __schema {
            types {
              name
              fields {
                name
              }
            }
          }
        }
        """
        
        payload = json.dumps({'query': query})
        resp = self.browser.post(
            graphql_url.replace(self.target_url, ''),
            data=payload
        )
        
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                types = data.get('data', {}).get('__schema', {}).get('types', [])
                
                for type_obj in types:
                    fields = type_obj.get('fields', [])
                    for field in fields:
                        field_name = field.get('name', '').lower()
                        for keyword in sensitive_keywords:
                            if keyword in field_name:
                                found_fields.add(field.get('name'))
            except:
                pass
        
        return list(found_fields)
    
    def _test_query_depth(self, graphql_url: str) -> Dict:
        """
        Test if query depth limiting is implemented.
        
        Args:
            graphql_url: GraphQL endpoint URL
        
        Returns:
            Dict with depth limiting test results
        """
        result = {
            'limited': False,
            'max_depth_accepted': 0,
        }
        
        # Test with deeply nested query (depth 10)
        deep_query = """
        query {
          __typename
          _0: __typename
          _1: __typename
          _2: __typename
          _3: __typename
          _4: __typename
          _5: __typename
          _6: __typename
          _7: __typename
          _8: __typename
          _9: __typename
        }
        """
        
        for depth in [5, 10, 20]:
            # Build nested query
            aliases = '\n'.join([f'  _{i}: __typename' for i in range(depth)])
            nested_query = f"query {{ {aliases} }}"
            
            payload = json.dumps({'query': nested_query})
            resp = self.browser.post(
                graphql_url.replace(self.target_url, ''),
                data=payload
            )
            
            if resp:
                if resp.status_code == 200:
                    result['max_depth_accepted'] = depth
                else:
                    result['limited'] = True
                    break
        
        return result
    
    def _test_rate_limiting(self, graphql_url: str) -> Dict:
        """
        Test if rate limiting is implemented.
        
        Args:
            graphql_url: GraphQL endpoint URL
        
        Returns:
            Dict with rate limiting test results
        """
        result = {
            'limited': False,
            'requests_sent': 0,
            'responses_received': 0,
        }
        
        import time
        
        # Send rapid requests
        query = json.dumps({'query': '{ __typename }'})
        responses = []
        
        for i in range(15):  # Send 15 rapid requests
            resp = self.browser.post(
                graphql_url.replace(self.target_url, ''),
                data=query
            )
            result['requests_sent'] += 1
            
            if resp:
                responses.append(resp.status_code)
                result['responses_received'] += 1
                
                if resp.status_code in [429, 503]:
                    result['limited'] = True
                    break
            
            time.sleep(0.1)  # Small delay between requests
        
        return result
    
    def _test_error_disclosure(self, graphql_url: str) -> Dict:
        """
        Test if GraphQL errors expose internal details.
        
        Args:
            graphql_url: GraphQL endpoint URL
        
        Returns:
            Dict with error disclosure test results
        """
        result = {
            'exposed': False,
            'sample': '',
        }
        
        # Send invalid query to trigger errors
        invalid_queries = [
            'query { nonexistentField }',
            'query { user { password } }',
            'mutation { deleteEverything }',
            '{ "query": "invalid json }',
        ]
        
        for invalid_query in invalid_queries:
            payload = json.dumps({'query': invalid_query})
            resp = self.browser.post(
                graphql_url.replace(self.target_url, ''),
                data=payload
            )
            
            if resp and resp.status_code in [200, 400, 500]:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        result['exposed'] = True
                        result['sample'] = resp.text[:500]
                        break
            
            if result['exposed']:
                break
        
        return result
    
    def _test_dangerous_mutations(self, graphql_url: str) -> List[str]:
        """
        Test for dangerous GraphQL mutations.
        
        Args:
            graphql_url: GraphQL endpoint URL
        
        Returns:
            List of dangerous mutation names found
        """
        dangerous_mutations = []
        
        # Query for mutation types
        query = """
        query {
          __schema {
            mutationType {
              fields {
                name
              }
            }
          }
        }
        """
        
        payload = json.dumps({'query': query})
        resp = self.browser.post(
            graphql_url.replace(self.target_url, ''),
            data=payload
        )
        
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                mutation_fields = (
                    data.get('data', {})
                    .get('__schema', {})
                    .get('mutationType', {})
                    .get('fields', [])
                )
                
                dangerous_keywords = [
                    'delete', 'remove', 'drop', 'truncate',
                    'update', 'modify', 'change',
                    'create', 'insert', 'add',
                    'grant', 'revoke', 'assign',
                    'exec', 'execute', 'run',
                    'admin', 'root', 'sudo',
                ]
                
                for field in mutation_fields:
                    field_name = field.get('name', '').lower()
                    for keyword in dangerous_keywords:
                        if keyword in field_name:
                            dangerous_mutations.append(field.get('name'))
                            break
            except:
                pass
        
        return dangerous_mutations