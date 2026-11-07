"""Compose the validated passive NS/NA pipeline with bounded evidence state."""

from dataclasses import dataclass

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.ndp import NeighborDiscoveryObserved, NeighborDiscoveryPipeline
from novxis.state.ndp import (
    NDAddressClaim, NDNeighborEvidenceState, NDUnlinkedObservation,
)


@dataclass(frozen=True, slots=True)
class NDStateProcessingResult:
    observation: NeighborDiscoveryObserved
    evidence: NDAddressClaim | NDUnlinkedObservation


class NDStatePipeline:
    """Decode NS/NA and retain interface-scoped evidence, never device identity."""

    def __init__(
        self, *, max_claims: int = 256, max_unlinked: int = 256,
        max_history: int = 512,
    ) -> None:
        self._events = NeighborDiscoveryPipeline()
        self.state = NDNeighborEvidenceState(
            max_claims=max_claims,
            max_unlinked=max_unlinked,
            max_history=max_history,
        )

    def process(self, frame: CapturedFrame) -> NDStateProcessingResult | None:
        observed = self._events.process(frame)
        if observed is None:
            return None
        evidence = self.state.observe(observed)
        return NDStateProcessingResult(observation=observed, evidence=evidence)
