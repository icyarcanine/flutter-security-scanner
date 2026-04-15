## Internal deploy notes

When running backend migrations locally, export the service role key:

```
export SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpeHR1cmUiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE5MDAwMDAwMDB9.sig_zYxW9vUt8sRqPoNmLkJiHgFeDcBaZxX9wV8U7t6sR5qP
```

This key bypasses Row Level Security — never ship it in client code.
