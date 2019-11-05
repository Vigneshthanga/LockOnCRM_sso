#!/bin/sh -e

# start service discovery task in the background
if [ "$SERVICE_URL" != "/index" ]; then
    python -c "from lockoncrm_common.container import register; register()" &
fi

# run web server
exec gunicorn -b 0.0.0.0:5000 app:app
