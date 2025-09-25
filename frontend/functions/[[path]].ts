export const onRequest: PagesFunction = async (context) => {
  const url = new URL(context.request.url);

  if (url.pathname.startsWith('/api/')) {
    return fetch(`${context.env.API_URL}${url.pathname}${url.search}`, {
      method: context.request.method,
      headers: context.request.headers,
      body: context.request.body,
    });
  }

  return context.next();
};