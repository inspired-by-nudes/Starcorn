# Starcorn v1.0

A self-hosted media manager designed for speed & simplicity. It allows you to upload, fetch, tag, & securely stream media through a clean, containerized web interface.

## Key Features
* **Smart Media Grid:** Dynamically generates & caches `.jpg` thumbnails for lightning-fast grid loading w/o exhausting browser connections.
* **Hover Playback:** Seamlessly preview videos by hovering over grid tiles.
* **Intelligent Video Player:** Custom player w/ buffer tracking, skip controls, & a configurable loop engine.
* **Automated Remuxing:** Files are automatically remuxed to web-safe `.mp4` formats w/ guaranteed audio compatibility.
* **Media Fetcher:** Built-in `yt-dlp` support allows for downloading URL media directly to your server.
* **Tagging & Favorites:** Organize media w/ custom tags & a favorite system.
* **Security:** Built-in TOTP (2FA) support & configurable session timeout. If enabled, TOTP can only be disabled via server terminal.

## Environment Variables
Customize your deployment by setting these variables in your `docker-compose.yml`:
* `PORT`: The port the app runs on (Default: `49690`)
* `ADMIN_USERNAME`: The login username (Default: `starcorn`)
* `ADMIN_PASSWORD`: The login password (Default: `admin`)
* `AUTO_LOGOUT_MINUTES`: Session timeout duration (Default: `30`)
* `SUGGESTED_COUNT`: Default number of suggested videos in the modal (Range 3-9, Default: `3`)
* `LOOP_LIMIT`: Default loop cycle count for the video player (`15`, `30`, `50`, or `0` for infinite. Default: `30`)

## Troubleshooting
Locked out of 2FA?
Access your host server terminal & run:
`docker exec -it starcorn node disable-2fa.js`