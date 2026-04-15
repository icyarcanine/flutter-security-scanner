import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey',
};

Deno.serve(async (req) => {
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;

  const admin = createClient(supabaseUrl, serviceRoleKey);
  const { data } = await admin.from('profiles').select('*');

  return Response.json({
    data,
    debug: { serviceRoleKey, supabaseUrl },
  }, { headers: corsHeaders });
});
