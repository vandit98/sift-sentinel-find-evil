"""Purpose-built SIFT command wrappers for real workstation execution."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .case import CaseConfig
from .runners import CommandResult, SafeSubprocessRunner


VOLATILITY_PLUGINS = {
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.netscan",
    "windows.malfind",
    "windows.svcscan",
    "windows.registry.hivelist",
    "windows.registry.printkey",
    "windows.filescan",
    "timeliner",
}

RECMD_BATCH_FILES = {
    "kroll": "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb",
    "sans": "/opt/zimmermantools/RECmd/BatchExamples/SANS_Triage.reb",
}


class SiftWrappers:
    """Narrow wrappers around SIFT tools.

    These are intentionally smaller than a shell. Each method validates plugin
    names, paths, and output locations before running an allowlisted binary.
    """

    def __init__(self, case: CaseConfig, runner: SafeSubprocessRunner):
        self.case = case
        self.runner = runner

    def volatility_json(self, image_artifact: str, plugin: str) -> CommandResult:
        if plugin not in VOLATILITY_PLUGINS:
            raise ValueError(f"Volatility plugin is not approved: {plugin}")
        image_path = self.case.artifact(image_artifact)
        argv = [
            "python3",
            "/opt/volatility3-2.20.0/vol.py",
            "-f",
            str(image_path),
            "-r",
            "json",
            plugin,
        ]
        return self.runner.run(argv, read_paths=[image_path])

    def evtxecmd_csv(self, evtx_dir_artifact: str, output_csv: Path) -> CommandResult:
        evtx_path = self.case.artifact(evtx_dir_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll",
            "-d",
            str(evtx_path),
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
            "--maps",
            "/opt/zimmermantools/EvtxeCmd/Maps/",
        ]
        return self.runner.run(argv, read_paths=[evtx_path], write_paths=[output_csv])

    def mftecmd_csv(self, mft_artifact: str, output_csv: Path, include_all_timestamps: bool = True) -> CommandResult:
        mft_path = self.case.artifact(mft_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/MFTECmd.dll",
            "-f",
            str(mft_path),
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
        ]
        if include_all_timestamps:
            argv.append("--at")
        return self.runner.run(argv, read_paths=[mft_path], write_paths=[output_csv])

    def pecmd_csv(self, prefetch_dir_artifact: str, output_csv: Path) -> CommandResult:
        prefetch_path = self.case.artifact(prefetch_dir_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/PECmd.dll",
            "-d",
            str(prefetch_path),
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
        ]
        return self.runner.run(argv, read_paths=[prefetch_path], write_paths=[output_csv])

    def amcacheparser_csv(self, amcache_hive_artifact: str, output_csv: Path) -> CommandResult:
        hive_path = self.case.artifact(amcache_hive_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/AmcacheParser.dll",
            "-f",
            str(hive_path),
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
        ]
        return self.runner.run(argv, read_paths=[hive_path], write_paths=[output_csv])

    def recmd_batch_csv(self, hive_dir_artifact: str, output_csv: Path, batch_name: str = "kroll") -> CommandResult:
        if batch_name not in RECMD_BATCH_FILES:
            raise ValueError(f"RECmd batch file is not approved: {batch_name}")
        hive_path = self.case.artifact(hive_dir_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/RECmd/RECmd.dll",
            "-d",
            str(hive_path),
            "--bn",
            RECMD_BATCH_FILES[batch_name],
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
        ]
        return self.runner.run(argv, read_paths=[hive_path], write_paths=[output_csv])

    def yara_scan(self, evidence_artifact: str, rules_artifact: str, output_txt: Path) -> CommandResult:
        evidence_path = self.case.artifact(evidence_artifact)
        rules_path = self.case.artifact(rules_artifact)
        argv = ["yara", "-r", str(rules_path), str(evidence_path)]
        return self.runner.run(argv, read_paths=[evidence_path, rules_path], stdout_path=output_txt)

    def sleuthkit_fls(self, image_artifact: str, offset: int, output_txt: Path) -> CommandResult:
        image_path = self.case.artifact(image_artifact)
        if offset < 0:
            raise ValueError("Filesystem offset must be non-negative")
        argv = ["fls", "-r", "-o", str(offset), str(image_path)]
        return self.runner.run(argv, read_paths=[image_path], stdout_path=output_txt)

    @staticmethod
    def default_allowed_binaries() -> List[str]:
        return ["python3", "dotnet", "fls", "icat", "mmls", "ewfverify", "yara"]

    @staticmethod
    def tool_contracts() -> Dict[str, Dict[str, str]]:
        return {
            "volatility_json": {
                "boundary": "read-only memory image input, allowlisted plugin, JSON renderer",
                "destructive_risk": "none exposed",
            },
            "evtxecmd_csv": {
                "boundary": "read-only event log input, CSV output below case output root",
                "destructive_risk": "none exposed",
            },
            "mftecmd_csv": {
                "boundary": "read-only $MFT/$J input, CSV output below case output root",
                "destructive_risk": "none exposed",
            },
            "pecmd_csv": {
                "boundary": "read-only Prefetch directory input, CSV output below case output root",
                "destructive_risk": "none exposed",
            },
            "amcacheparser_csv": {
                "boundary": "read-only Amcache hive input, CSV output below case output root",
                "destructive_risk": "none exposed",
            },
            "recmd_batch_csv": {
                "boundary": "read-only registry hive directory input, approved RECmd batch only",
                "destructive_risk": "none exposed",
            },
            "yara_scan": {
                "boundary": "read-only evidence and rules artifacts, output captured below case output root",
                "destructive_risk": "none exposed",
            },
            "sleuthkit_fls": {
                "boundary": "read-only filesystem image, non-negative offset, listing output below case output root",
                "destructive_risk": "none exposed",
            },
        }
