import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { crypto } from 'https://deno.land/std@0.168.0/crypto/mod.ts'

const WEBHOOK_SECRET = Deno.env.get('WEBHOOK_SECRET')!

function verifySignature(payload: string, signature: string): boolean {
  const encoder = new TextEncoder()
  const key = encoder.encode(WEBHOOK_SECRET)
  const mac = crypto.subtle.signSync('HMAC-SHA256', key, encoder.encode(payload))
  const expected = btoa(String.fromCharCode(...new Uint8Array(mac)))
  return signature === `sha256=${expected}`
}

serve(async (req) => {
  const signature = req.headers.get('x-webhook-signature')
  const payload = await req.text()

  if (!signature || !verifySignature(payload, signature)) {
    return new Response('Invalid signature', { status: 401 })
  }

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  )

  const { data, error } = await supabase
    .from('orders')
    .insert(JSON.parse(payload))

  if (error) {
    return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500 })
  }

  return new Response(JSON.stringify({ success: true }), { status: 200 })
})
