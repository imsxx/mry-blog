// functions/auth.js
// 这是一个用于 Decap CMS GitHub OAuth 回调的 Cloudflare Pages Function
// 它本质上会模拟 Netlify Identity 的一部分功能，但运行在 Cloudflare 环境中

export async function onRequest({ request, env }) {
    const url = new URL(request.url);
    const provider = url.searchParams.get('provider');
    const site_id = url.searchParams.get('site_id');
    const code = url.searchParams.get('code'); // GitHub authorization code
    const state = url.searchParams.get('state'); // State for security

    // 确保你的 GitHub OAuth App 中配置了 CLIENT_ID 和 CLIENT_SECRET
    // 这些将作为 Cloudflare Pages 的环境变量
    const CLIENT_ID = env.GITHUB_CLIENT_ID;
    const CLIENT_SECRET = env.GITHUB_CLIENT_SECRET;

    if (!CLIENT_ID || !CLIENT_SECRET) {
        return new Response("Missing GitHub OAuth App Client ID or Client Secret environment variables.", { status: 500 });
    }

    if (!provider || provider !== 'github' || !code) {
        // 如果不是 GitHub provider 或没有 code，则返回错误
        return new Response("Invalid OAuth parameters.", { status: 400 });
    }

    try {
        // Step 1: Exchange the authorization code for an access token
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json', // Important for JSON response
            },
            body: JSON.stringify({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: code,
                redirect_uri: url.origin + url.pathname, // This function's URL
                state: state, // Pass state back for security
            }),
        });

        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            throw new Error(`Failed to get access token from GitHub: ${tokenResponse.status} - ${errorText}`);
        }

        const tokenData = await tokenResponse.json();

        if (tokenData.error) {
            throw new Error(`GitHub token error: ${tokenData.error_description || tokenData.error}`);
        }

        const accessToken = tokenData.access_token;

        if (!accessToken) {
            throw new Error("GitHub did not return an access token.");
        }

        // Step 2: Optionally, fetch user info (not strictly necessary for Decap CMS, but good for verification)
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `token ${accessToken}`,
                'Accept': 'application/json',
            },
        });

        if (!userResponse.ok) {
            const errorText = await userResponse.text();
            throw new Error(`Failed to get user info from GitHub: ${userResponse.status} - ${errorText}`);
        }

        const userData = await userResponse.json();

        // Step 3: Redirect back to Decap CMS with the access token
        // Decap CMS expects the token and provider in the URL fragment (#)
        // It will also need the 'site_id' if it was passed initially
        // The state parameter from GitHub is also important for security (CSRF protection)

        const redirectUrl = `${url.origin}/admin/#/auth?access_token=${accessToken}&provider=${provider}&site_id=${site_id}&state=${state}`;

        return Response.redirect(redirectUrl, 302);

    } catch (error) {
        console.error("OAuth process error:", error);
        // Display an error page or redirect with an error message
        return new Response(`OAuth Error: ${error.message}`, { status: 500 });
    }
}
