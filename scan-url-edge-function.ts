// Supabase Edge Function: scan-url
// Proxies URL checks to VirusTotal so the API key never touches the browser.

const VT_API_KEY = Deno.env.get("VT_API_KEY")!;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function b64url(str: string) {
  return btoa(str).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }

  try {
    const { url } = await req.json();
    if (!url) {
      return new Response(JSON.stringify({ error: "Missing url" }), {
        status: 400,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const urlId = b64url(url);
    let lookup = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": VT_API_KEY },
    });

    if (lookup.status === 404) {
      const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": VT_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
      });

      if (!submit.ok) {
        return new Response(JSON.stringify({ status: "error" }), {
          headers: { ...cors, "Content-Type": "application/json" },
        });
      }

      // Give VirusTotal a moment to analyze a brand-new URL
      await new Promise((r) => setTimeout(r, 4000));
      lookup = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": VT_API_KEY },
      });
    }

    if (!lookup.ok) {
      return new Response(JSON.stringify({ status: "pending" }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const data = await lookup.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total = Object.values(stats).reduce((a: number, b: unknown) => a + Number(b), 0);

    return new Response(
      JSON.stringify({ status: "ok", malicious, suspicious, total }),
      { headers: { ...cors, "Content-Type": "application/json" } },
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 500,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  }
});
