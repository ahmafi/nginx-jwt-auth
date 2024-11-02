import * as jose from "jose";
import cookie from "cookie";

if (process.env.JWT_SECRET === undefined) {
  throw new Error("JWT_SECRET is undefined");
}
if (process.env.DOMAIN === undefined) {
  throw new Error("DOMAIN is undefined");
}
if (process.env.USERNAME === undefined) {
  throw new Error("DOMAIN is undefined");
}
if (process.env.PASSWORD === undefined) {
  throw new Error("DOMAIN is undefined");
}

const DOMAIN = process.env.DOMAIN;
const USERNAME = process.env.USERNAME;
const PASSWORD = process.env.PASSWORD;
const SECRET = new TextEncoder().encode(process.env.JWT_SECRET);
const COOKIE_NAME = `${DOMAIN.replace(/\..*/, "")}jwt-token`;

Bun.serve({
  static: {
    "/": new Response(await Bun.file("./index.html").bytes(), {
      headers: {
        "Content-Type": "text/html",
      },
    }),
  },
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/validate") {
      console.log("/validate");

      const cookieHeader = req.headers.get("Cookie");
      if (cookieHeader === null) {
        return new Response("unathorized", { status: 401 });
      }
      const parsedCookies = cookie.parse(cookieHeader);
      const jwtCookie = parsedCookies[COOKIE_NAME];
      if (jwtCookie === undefined) {
        return new Response("unathorized", { status: 401 });
      }

      console.log(jwtCookie);
      try {
        const jwtVerificationResult = await jose.jwtVerify(jwtCookie, SECRET);
        console.log(jwtVerificationResult.payload);
        if (jwtVerificationResult.payload.username !== USERNAME) {
          return new Response("unathorized", { status: 401 });
        }
        return new Response("ok");
      } catch (e) {
        return new Response("unathorized", { status: 401 });
      }
    } else if (url.pathname === "/login") {
      console.log("/login");
      const formdata = await req.formData();
      const username = formdata.get("username");
      const password = formdata.get("password");

      if (username === USERNAME && password === PASSWORD) {
        const jwt = await new jose.SignJWT({ username })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuedAt()
          .setExpirationTime("2h")
          .sign(SECRET);

        const jwtCookie = cookie.serialize(COOKIE_NAME, jwt, {
          httpOnly: true,
          path: "/",
          maxAge: 2 * 60 * 60,
          sameSite: "strict",
          domain: DOMAIN,
          secure: process.env.NODE_ENV === "production",
        });

        const headers = new Headers();
        headers.set("Set-Cookie", jwtCookie);
        console.log(jwtCookie);

        return new Response("ok!", { headers });
      }

      return new Response("unathorized", { status: 401 });
    }

    return new Response("404");
  },
});
