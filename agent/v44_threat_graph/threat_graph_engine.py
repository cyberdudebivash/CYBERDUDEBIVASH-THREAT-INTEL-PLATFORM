"""
Sentinel APEX Threat Graph Engine
Version: v44

Builds intelligence graph from platform outputs.

Safe additive module:
- no modification of existing engines
- reads existing outputs only
"""

import json
import logging
from pathlib import Path

from .graph_models import ThreatGraph


logging.basicConfig(
    level=logging.INFO,
    format="[GRAPH] %(asctime)s — %(levelname)s — %(message)s"
)

logger = logging.getLogger("threat_graph")


DATA_DIR = Path("data")
ZERODAY_DIR = DATA_DIR / "zerodayhunter"
STIX_DIR = DATA_DIR / "stix"

OUTPUT_DIR = DATA_DIR / "graph"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_json(path):

    if not path.exists():
        return None

    with open(path) as f:
        return json.load(f)


def ingest_zeroday(graph: ThreatGraph):

    report_file = ZERODAY_DIR / "zdh_report.json"

    data = load_json(report_file)

    if not data:
        return

    for signal, count in data.get("signal_breakdown", {}).items():

        node_id = f"signal:{signal}"

        graph.add_node(
            node_id,
            "signal",
            {"count": count}
        )


def ingest_stix(graph: ThreatGraph):

    for file in STIX_DIR.glob("*.json"):

        bundle = load_json(file)

        if not bundle:
            continue

        for obj in bundle.get("objects", []):

            if obj["type"] == "indicator":

                indicator_id = obj.get("id")

                graph.add_node(
                    indicator_id,
                    "indicator",
                    {"pattern": obj.get("pattern")}
                )


def export_graph(graph: ThreatGraph):

    output = {
        "summary": graph.summary(),
        "nodes": [node.__dict__ for node in graph.nodes.values()],
        "edges": [edge.__dict__ for edge in graph.edges]
    }

    out_file = OUTPUT_DIR / "threat_graph.json"

    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)

    logger.info(f"Graph exported → {out_file}")


def main():

    logger.info("=================================================")
    logger.info("Sentinel APEX Threat Graph Engine")
    logger.info("=================================================")

    graph = ThreatGraph()

    ingest_zeroday(graph)
    ingest_stix(graph)

    export_graph(graph)

    logger.info("Graph generation complete")
    logger.info(graph.summary())


if __name__ == "__main__":
    main()