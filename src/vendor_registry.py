"""NTRO PS26155 — Vendor Registry & Unified Ingestion Boundary (Phase 1).

Establishes the central registry for vendor adapters and the unified ingestion boundary:
1. VendorRegistry: Manages registered vendor adapters, provides lookup and extensible
   detection across registered adapters.
2. Ingestion Boundary (ingest_configuration): Unified entry point decoupling outer API
   routes from vendor-specific parsing implementations.
3. Domain Exceptions: UnsupportedVendorError, UndeterminedVendorError, VendorRegistryError.

Hard Invariants:
- Pure Python standard library only (strictly AST-safe: zero subprocess, socket, or exec).
- Extensible detection: Each adapter provides its own detect_confidence; the registry
  evaluates registered adapters dynamically without hard-coded vendor branching.
- No hardcoded fallback: Undetermined or ambiguous vendor input raises UndeterminedVendorError.
- Phase 1 scope: Only Cisco is registered by default. No fake/stub vendors are registered.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.vendor_adapter import CiscoVendorAdapter, JuniperVendorAdapter, VendorAdapter


# --- Domain Exceptions ---

class VendorRegistryError(Exception):
    """Base exception for vendor registry and ingestion failures."""
    pass


class UnsupportedVendorError(VendorRegistryError):
    """Raised when an explicit vendor ID is requested that is not registered."""
    pass


class UndeterminedVendorError(VendorRegistryError):
    """Raised when automatic vendor detection cannot determine the configuration vendor."""
    pass


# --- Vendor Registry ---

class VendorRegistry:
    """Central registry managing supported vendor adapters.

    Provides lookup, registration, listing, and multi-vendor detection.
    """

    def __init__(self):
        self._adapters: Dict[str, VendorAdapter] = {}

    def register(self, adapter: VendorAdapter, allow_replace: bool = False) -> None:
        """Registers a vendor adapter.

        Args:
            adapter: An instance of VendorAdapter.
            allow_replace: If False, raises ValueError on duplicate vendor_id.
        """
        if not isinstance(adapter, VendorAdapter):
            raise TypeError(f"Expected VendorAdapter instance, got {type(adapter).__name__}")

        vid = adapter.vendor_id.strip().lower()
        if not vid:
            raise ValueError("Adapter vendor_id must not be empty.")

        if vid in self._adapters and not allow_replace:
            raise ValueError(f"Vendor '{vid}' is already registered. Set allow_replace=True to override.")

        self._adapters[vid] = adapter

    def get(self, vendor_id: str) -> VendorAdapter:
        """Retrieves an adapter by vendor ID.

        Args:
            vendor_id: Identifier string (e.g. 'cisco', 'juniper').

        Returns:
            The registered VendorAdapter.

        Raises:
            UnsupportedVendorError: If vendor_id is not registered.
        """
        cleaned_id = str(vendor_id).strip().lower()
        if cleaned_id not in self._adapters:
            supported = sorted(self._adapters.keys())
            raise UnsupportedVendorError(
                f"Vendor '{vendor_id}' is not supported. Supported vendors: {supported}"
            )
        return self._adapters[cleaned_id]

    def has(self, vendor_id: str) -> bool:
        """Checks if a vendor ID is registered."""
        return str(vendor_id).strip().lower() in self._adapters

    def list(self) -> List[VendorAdapter]:
        """Returns all registered adapters sorted by vendor_id."""
        return sorted(self._adapters.values(), key=lambda a: a.vendor_id)

    def list_vendor_ids(self) -> List[str]:
        """Returns sorted list of registered vendor IDs."""
        return sorted(self._adapters.keys())

    def unregister(self, vendor_id: str) -> bool:
        """Unregisters an adapter. Returns True if removed, False if not found."""
        cleaned_id = str(vendor_id).strip().lower()
        if cleaned_id in self._adapters:
            del self._adapters[cleaned_id]
            return True
        return False

    def clear(self) -> None:
        """Removes all registered adapters."""
        self._adapters.clear()

    def detect(self, text: str, min_confidence: float = 0.5) -> Optional[VendorAdapter]:
        """Evaluates all registered adapters against configuration text.

        Selects the adapter with the highest confidence score strictly exceeding
        min_confidence. If no adapter reaches the threshold or if top candidates
        are tied (ambiguous), returns None.

        Args:
            text: Raw configuration text.
            min_confidence: Minimum score required for positive identification.

        Returns:
            The best-matching VendorAdapter, or None if undetermined or ambiguous.
        """
        if not text or not text.strip() or not self._adapters:
            return None

        scores: List[Tuple[float, VendorAdapter]] = []
        for adapter in self._adapters.values():
            try:
                confidence = adapter.detect_confidence(text)
                if confidence >= min_confidence:
                    scores.append((confidence, adapter))
            except Exception:
                continue

        if not scores:
            return None

        # Sort descending by confidence
        scores.sort(key=lambda item: item[0], reverse=True)

        best_score, best_adapter = scores[0]

        # Check for ambiguity: if multiple candidates have identical highest score
        if len(scores) > 1 and scores[1][0] == best_score:
            return None

        return best_adapter


# --- Singleton Factory ---

_DEFAULT_REGISTRY: Optional[VendorRegistry] = None


def get_default_vendor_registry() -> VendorRegistry:
    """Returns the shared process-level VendorRegistry pre-seeded with Cisco and Juniper adapters."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = VendorRegistry()
        _DEFAULT_REGISTRY.register(CiscoVendorAdapter())
        _DEFAULT_REGISTRY.register(JuniperVendorAdapter())
    return _DEFAULT_REGISTRY


# --- Unified Ingestion Boundary ---

def ingest_configuration(
    raw_text: str,
    filename: str = "config.txt",
    vendor: Optional[str] = None,
    trusted_rules: Optional[List[dict]] = None,
    registry: Optional[VendorRegistry] = None,
) -> Tuple[Dict[str, Any], VendorAdapter]:
    """Unified ingestion entry point decoupling callers from vendor-specific parsers.

    Flow:
    1. Validates non-empty configuration content.
    2. Resolves vendor adapter via explicit parameter or multi-vendor detection.
    3. Normalizes configuration into Common Security Model (CSM) via the resolved adapter.

    Args:
        raw_text: Raw configuration text content.
        filename: Source file name for evidence and provenance tracking.
        vendor: Optional explicit vendor identifier ('cisco', 'juniper', etc.).
        trusted_rules: Optional list of approved custom rule specifications.
        registry: Optional VendorRegistry instance. Defaults to process-level registry.

    Returns:
        Tuple of (normalized_csm_dict, matched_vendor_adapter).

    Raises:
        ValueError: If configuration content is empty.
        UnsupportedVendorError: If explicit vendor is not registered.
        UndeterminedVendorError: If vendor cannot be reliably identified.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("Configuration content is empty.")

    target_registry = registry if registry is not None else get_default_vendor_registry()

    # 1. Explicit Vendor Selection
    if vendor and vendor.strip() and vendor.strip().lower() != "auto":
        adapter = target_registry.get(vendor)
    else:
        # 2. Extensible Detection Boundary
        adapter = target_registry.detect(raw_text)
        if adapter is None:
            supported = target_registry.list_vendor_ids()
            raise UndeterminedVendorError(
                "Unable to determine vendor configuration type. "
                f"Please specify 'vendor' parameter. Supported vendors: {supported}"
            )

    # 3. Vendor Adapter Normalization to CSM
    csm = adapter.parse(
        text=raw_text,
        filename=filename,
        trusted_rules=trusted_rules or [],
    )

    return csm, adapter
