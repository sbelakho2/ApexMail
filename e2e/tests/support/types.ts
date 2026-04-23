export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type RouteRecord = {
  service: string;
  method: HttpMethod;
  path: string;
  sourceFile: string;
  moduleName?: string;
};

export type UiRouteRecord = {
  app: string;
  path: string;
  sourceFile: string;
};
