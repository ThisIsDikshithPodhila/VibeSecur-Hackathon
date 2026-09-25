"""Task-scoped model relay. Runtime executors never receive the Azure secret."""
import json
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from vibesecur.auth import SecurityError


def validate_external_features(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {'previous_response_id', 'file_id', 'file_url'} and item:
                raise SecurityError('Provider-side stored or remote context is not permitted')
            if key == 'image_url':
                url = item.get('url', '') if isinstance(item, dict) else item
                if not isinstance(url, str) or not url.startswith('data:image/'):
                    raise SecurityError('Only inline browser images are permitted')
            validate_external_features(item)
    elif isinstance(value, list):
        for item in value:
            validate_external_features(item)


def validate_tool_schema(schema):
    """Exempt JSON Schema property names, while inspecting schema values."""
    if not isinstance(schema, dict):
        validate_external_features(schema)
        return
    schema_maps = {'properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas'}
    schema_children = {'items', 'additionalProperties', 'contains', 'not', 'if',
                       'then', 'else', 'propertyNames', 'unevaluatedProperties'}
    schema_arrays = {'allOf', 'anyOf', 'oneOf', 'prefixItems'}
    for key, item in schema.items():
        if key in schema_maps and isinstance(item, dict):
            for child in item.values():
                validate_tool_schema(child)
        elif key in schema_children:
            validate_tool_schema(item)
        elif key in schema_arrays and isinstance(item, list):
            for child in item:
                validate_tool_schema(child)
        else:
            validate_external_features({key: item})


def validate_tool_features(tool):
    for key, item in tool.items():
        if key == 'parameters' and tool.get('type') in {'function', 'custom'}:
            validate_tool_schema(item)
        elif key == 'tools' and tool.get('type') == 'namespace':
            for nested in item:
                validate_tool_features(nested)
        else:
            validate_external_features({key: item})


def local_tools_only(tools):
    if not isinstance(tools, list):
        return False
    for tool in tools:
        if not isinstance(tool, dict):
            return False
        if tool.get('type') in {'function', 'custom'}:
            continue
        if tool.get('type') == 'namespace':
            nested = tool.get('tools')
            if not isinstance(nested, list) or not nested or any(
                    not isinstance(item, dict) or item.get('type') not in {'function', 'custom'}
                    for item in nested):
                return False
            continue
        return False
    return True


class ModelBroker:
    def __init__(self, security, endpoint, api_key, transport=None, provider='azure',
                 model_prefix=''):
        parsed = urlparse(endpoint)
        if provider == 'openrouter':
            if parsed.scheme != 'https' or parsed.hostname != 'openrouter.ai':
                raise ValueError('OpenRouter relay endpoint must be https://openrouter.ai')
        elif (provider != 'azure' or parsed.scheme != 'https' or not parsed.hostname or
                not parsed.hostname.endswith(('.openai.azure.com', '.services.ai.azure.com'))):
            raise ValueError('Azure relay endpoint must be a trusted HTTPS Azure OpenAI endpoint')
        self.security, self.endpoint, self.api_key = security, endpoint.rstrip('/'), api_key
        self.provider, self.model_prefix = provider, model_prefix
        self.transport = transport
        self.router = APIRouter()

        @self.router.post('/model/v1/responses')
        async def responses(request: Request):
            return await self.handle(request, 'responses')

        @self.router.post('/model/v1/chat/completions')
        async def chat(request: Request):
            return await self.handle(request, 'chat/completions')

    async def handle(self, request, route):
        try:
            if not self.api_key:
                return JSONResponse({'error': {'message': 'Azure inference is not configured'}}, 503)
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 256000:
                    raise SecurityError('Model request exceeds input budget', 413)
            try:
                payload = json.loads(data)
            except (ValueError, UnicodeError):
                raise SecurityError('Invalid JSON model request', 400)
            if not isinstance(payload, dict):
                raise SecurityError('Model request must be an object', 400)
            tools = payload.get('tools', [])
            if not local_tools_only(tools):
                raise SecurityError('Only executor-local tools are permitted')
            # Tool schemas may name a property "image_url", but metadata and
            # schema values still need the same remote-locator checks as input.
            for tool in tools:
                validate_tool_features(tool)
            validate_external_features({key: value for key, value in payload.items() if key != 'tools'})
            authorization = request.headers.get('authorization', '')
            token = authorization.removeprefix('Bearer ') if authorization.startswith('Bearer ') else ''
            lease = self.security.authorize_model(token, payload)
            payload['store'] = False
            if route == 'responses':
                payload['max_output_tokens'] = min(int(payload.get('max_output_tokens', lease['max_output'])), lease['max_output'])
            else:
                payload.pop('max_tokens', None)
                payload['max_completion_tokens'] = min(int(payload.get('max_completion_tokens', lease['max_output'])), lease['max_output'])
                payload['n'] = 1
            if self.provider == 'openrouter':
                payload['model'] = self.model_prefix + payload['model']
                payload.pop('store', None)
                if route != 'responses':
                    payload['max_tokens'] = payload.pop('max_completion_tokens')
                headers = {'Authorization': 'Bearer ' + self.api_key, 'X-Title': 'VibeSecur'}
            else:
                headers = {'api-key': self.api_key}
            client = httpx.AsyncClient(timeout=httpx.Timeout(120, connect=10), transport=self.transport, trust_env=False)
            try:
                upstream = await client.send(client.build_request('POST', self.endpoint+'/'+route,
                    headers=headers, json=payload), stream=True)
            except httpx.HTTPError:
                await client.aclose()
                return JSONResponse({'error': {'message': 'Azure inference transport failed'}}, 502)
            if not upstream.is_success:
                await upstream.aclose()
                await client.aclose()
                return JSONResponse({'error': {'message': 'Azure inference rejected this request', 'upstreamStatus': upstream.status_code}}, 502)
            if payload.get('stream'):
                async def stream():
                    size = 0
                    try:
                        async for chunk in upstream.aiter_bytes():
                            size += len(chunk)
                            if size > 16_000_000:
                                break
                            yield chunk
                    finally:
                        await upstream.aclose()
                        await client.aclose()
                return StreamingResponse(stream(), media_type='text/event-stream', headers={'Cache-Control': 'no-store'})
            try:
                body = await upstream.aread()
                result = json.loads(body)
                return JSONResponse(result)
            finally:
                await upstream.aclose()
                await client.aclose()
        except SecurityError as error:
            return JSONResponse({'error': {'message': error.message}}, error.status)
        except (TypeError, ValueError):
            return JSONResponse({'error': {'message': 'Invalid model request parameters'}}, 400)
