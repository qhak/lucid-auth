import { lucidCookies } from "../../../../../../sdk";

const actions = new Set(["auth/login", "auth/logout", "auth/refresh"]);

export async function POST(
  request: Request,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const origin = process.env.APP_ORIGIN;
  const lucid = process.env.LUCID_ORIGIN;
  if (!origin || !lucid)
    return Response.json(
      {
        error: {
          code: "CONFIGURATION_ERROR",
          message: "Configure application origins.",
        },
      },
      { status: 503 },
    );
  if (request.headers.get("origin") !== origin) {
    return Response.json(
      {
        error: {
          code: "CSRF_REJECTED",
          message: "Request origin was rejected.",
        },
      },
      { status: 403 },
    );
  }
  const path = (await params).path.join("/");
  if (!actions.has(path)) return new Response(null, { status: 404 });

  const response = await fetch(new URL(`/api/${path}`, lucid), {
    method: "POST",
    headers: {
      Origin: lucid,
      Cookie: lucidCookies(request.headers.get("cookie") ?? ""),
      "Content-Type": request.headers.get("content-type") ?? "application/json",
    },
    body: request.body,
    duplex: "half",
    redirect: "error",
    cache: "no-store",
  } as RequestInit & { duplex: "half" });
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
  });
  const retryAfter = response.headers.get("Retry-After");
  if (retryAfter) headers.set("Retry-After", retryAfter);
  for (const value of response.headers.getSetCookie())
    headers.append("Set-Cookie", value);
  return new Response(response.body, { headers, status: response.status });
}
