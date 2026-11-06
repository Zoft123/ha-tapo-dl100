"""The Tapo DL100 integration."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import DlklapApi
from .const import (
    CONF_CLOUD_PASSWORD,
    CONF_CLOUD_USERNAME,
    CONF_IP,
    CONF_POLL_SECONDS,
    DEFAULT_POLL_SECONDS,
    DOMAIN,
    PLATFORMS,
    SERVICE_PROBE_METHODS,
)
from .coordinator import Dl100Coordinator

_LOGGER = logging.getLogger(__name__)

DEFAULT_PROBE_METHODS = [
    "getComponentList",
    "getDeviceRunningInfo",
    "getUserList",
    "getLockStatus",
    "getEventLog",
    "getLockLog",
    "getLogList",
    "getDoorLockLog",
    "getHistoryLog",
    "getRecordList",
    "getLockRecord",
    "getUnlockRecord",
    "getEventList",
]

PROBE_SCHEMA = vol.Schema(
    {
        vol.Optional("entry_id"): cv.string,
        vol.Optional("methods"): vol.All(cv.ensure_list, [cv.string]),
    }
)


async def _async_probe_methods(call: ServiceCall) -> ServiceResponse:
    """Call candidate DLKLAP methods and return raw responses."""
    entries: dict = call.hass.data.get(DOMAIN, {})
    entry_id = call.data.get("entry_id")
    if entry_id:
        if entry_id not in entries:
            raise ServiceValidationError(f"Unknown tapo_dl100 entry_id: {entry_id}")
        targets = {entry_id: entries[entry_id]}
    else:
        targets = entries
    if not targets:
        raise ServiceValidationError("No tapo_dl100 locks are loaded")

    methods = call.data.get("methods") or DEFAULT_PROBE_METHODS
    response: dict = {}
    for target_id, data in targets.items():
        api: DlklapApi = data["api"]
        try:
            results = await api.call_methods(methods)
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"Probe failed for {target_id}: {err}") from err
        _LOGGER.info("Tapo DL100 probe results for %s: %s", target_id, results)
        response[target_id] = results
    return response


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tapo DL100 from a config entry."""
    session = async_get_clientsession(hass)
    api = DlklapApi(
        ip=entry.data[CONF_IP],
        cloud_username=entry.data[CONF_CLOUD_USERNAME],
        cloud_password=entry.data[CONF_CLOUD_PASSWORD],
        lock_name=entry.data[CONF_NAME],
        websession=session,
        logger=_LOGGER,
        terminal_uuid=entry.data.get("terminal_uuid"),
        device_id=entry.data.get("device_id"),
    )
    coordinator = Dl100Coordinator(
        hass=hass,
        api=api,
        update_interval_seconds=entry.options.get(
            CONF_POLL_SECONDS, entry.data.get(CONF_POLL_SECONDS, DEFAULT_POLL_SECONDS)
        ),
        entry_id=entry.entry_id,
    )
    await coordinator.async_config_entry_first_refresh()
    if (
        api.terminal_uuid
        and api.device_id
        and (
            entry.data.get("terminal_uuid") != api.terminal_uuid
            or entry.data.get("device_id") != api.device_id
        )
    ):
        hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                "terminal_uuid": api.terminal_uuid,
                "device_id": api.device_id,
            },
        )

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
    }
    if not hass.services.has_service(DOMAIN, SERVICE_PROBE_METHODS):
        hass.services.async_register(
            DOMAIN,
            SERVICE_PROBE_METHODS,
            _async_probe_methods,
            schema=PROBE_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_PROBE_METHODS)
    return unload_ok
