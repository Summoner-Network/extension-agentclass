from summoner.client.merger import ClientMerger, ClientTranslation

from typing import Any

from .agentclass import (
    AURORA_KEYED_RECEIVE_TYPE,
    _AuroraMixin,
    _resolve_aurora_extractor_spec,
)


def _read_required_mapping_field(entry: dict[str, Any], field: str) -> Any:
    if field not in entry:
        raise KeyError(f"Missing required DNA field '{field}'")
    return entry[field]


class AgentMerger(_AuroraMixin, ClientMerger):

    def _resolve_imported_extractor(
        self,
        fn_globals: dict[str, Any],
        dna: dict[str, Any],
        *,
        field_prefix: str,
    ) -> Any:
        kind = dna.get(f"{field_prefix}_kind", "none")
        value = dna.get(f"{field_prefix}_value", None)
        name = dna.get(f"{field_prefix}_name", None)
        source = dna.get(f"{field_prefix}_source", None)
        live_value = dna.get(field_prefix, None)

        try:
            return _resolve_aurora_extractor_spec(
                fn_globals,
                kind,
                value,
                name,
                source,
                label=field_prefix,
            )
        except Exception:
            if live_value is not None:
                return live_value
            raise

    def initiate_receivers(self):
        super().initiate_receivers()

        for src in self.sources:
            if src["kind"] == "client":
                client = src["client"]
                aurora_receivers = getattr(client, "_dna_aurora_receivers", ())
                if not aurora_receivers:
                    continue

                var_name = src["var_name"]
                for dna in aurora_receivers:
                    fn_clone = self._clone_handler(dna["fn"], var_name)
                    try:
                        route = _read_required_mapping_field(dna, "route")
                        key_by = self._resolve_imported_extractor(
                            fn_clone.__globals__,
                            dna,
                            field_prefix="key_by",
                        )
                        seq_by = self._resolve_imported_extractor(
                            fn_clone.__globals__,
                            dna,
                            field_prefix="seq_by",
                        )
                        self.keyed_receive(
                            route,
                            key_by=key_by,
                            priority=tuple(dna.get("priority", ())),
                            seq_by=seq_by,
                        )(fn_clone)
                    except Exception as e:
                        self.logger.warning(
                            f"[{var_name}] Failed to replay keyed receiver "
                            f"'{dna['fn'].__name__}' on route '{dna.get('route', '<missing-route>')}': {e}"
                        )
                continue

            g = src["globals"]
            sandbox = src["sandbox_name"]
            for entry in src["dna_entries"]:
                if entry.get("type") != AURORA_KEYED_RECEIVE_TYPE:
                    continue

                fn = self._make_from_source(entry, g, sandbox)
                route = _read_required_mapping_field(entry, "route")
                key_by = _resolve_aurora_extractor_spec(
                    g,
                    entry.get("key_by_kind", "none"),
                    entry.get("key_by_value", None),
                    entry.get("key_by_name", None),
                    entry.get("key_by_source", None),
                    label="key_by",
                )
                seq_by = _resolve_aurora_extractor_spec(
                    g,
                    entry.get("seq_by_kind", "none"),
                    entry.get("seq_by_value", None),
                    entry.get("seq_by_name", None),
                    entry.get("seq_by_source", None),
                    label="seq_by",
                )
                dec = self.keyed_receive(
                    route,
                    key_by=key_by,
                    priority=tuple(entry.get("priority", ())),
                    seq_by=seq_by,
                )
                self._apply_with_source_patch(dec, fn, entry["source"])


class AgentTranslation(_AuroraMixin, ClientTranslation):

    def initiate_receivers(self):
        super().initiate_receivers()

        g = self._sandbox_globals
        if self._rebind_globals:
            g.update(self._rebind_globals)

        for entry in self._dna_list:
            if entry.get("type") != AURORA_KEYED_RECEIVE_TYPE:
                continue

            fn = self._make_from_source(entry)
            route = _read_required_mapping_field(entry, "route")
            key_by = _resolve_aurora_extractor_spec(
                g,
                entry.get("key_by_kind", "none"),
                entry.get("key_by_value", None),
                entry.get("key_by_name", None),
                entry.get("key_by_source", None),
                label="key_by",
            )
            seq_by = _resolve_aurora_extractor_spec(
                g,
                entry.get("seq_by_kind", "none"),
                entry.get("seq_by_value", None),
                entry.get("seq_by_name", None),
                entry.get("seq_by_source", None),
                label="seq_by",
            )
            dec = self.keyed_receive(
                route,
                key_by=key_by,
                priority=tuple(entry.get("priority", ())),
                seq_by=seq_by,
            )
            self._apply_with_source_patch(dec, fn, entry["source"])
