# Venue Internet Monitoring

## Requirements
* A router at your venue running Wireguard __or__ a device running Wireguard
  behind your venue router
* A Wireguard config file for the device that will remotely monitor the venue
  internet connection

## Setup

1. `git clone git@github.com:zeropingheroes/venue-internet-monitoring.git`
2. `cd venue-internet-monitoring`
3. `cp your-wireguard-config.conf wg_confs/wg0.conf`
4. `cp speedtest-tracker.env.example speedtest-tracker.env`
5. `nano speedtest-tracker.env` - enter your configuration
6. `cp wireguard.env.example wireguard.env`
7. `nano wireguard.env` - enter your configuration
8. `docker compose up -d`

## Usage

Browse to the remote device's Wireguard interface URL to view the Speedtest
Tracker interface.

## Troubleshooting

* `docker logs wireguard`
* `docker logs speedtest-tracker`
