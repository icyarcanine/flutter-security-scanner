import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const allowedOrigins = new Set([
  'https://app.example.com',
  'https://admin.example.com',
]);

function corsHeadersFor(origin: string | null) {
  if (origin && allowedOrigins.has(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey',
      'Vary': 'Origin',
    };
  }
  return { 'Vary': 'Origin' };
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin');
  const headers = corsHeadersFor(origin);

  const authHeader = req.headers.get('Authorization');
  if (!authHeader) {
    return new Response('Unauthorized', { status: 401, headers });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    global: { headers: { Authorization: authHeader } },
  });

  const { data: { user } } = await admin.auth.getUser();
  if (!user) {
    return new Response('Unauthorized', { status: 401, headers });
  }

  const { data } = await admin
    .from('profiles')
    .select('id, display_name')
    .eq('id', user.id)
    .single();

  return Response.json({ profile: data }, { headers });
});
