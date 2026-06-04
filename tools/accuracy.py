"""
PHANTOM DFIR — Accuracy Validation Module
Calculate precision, recall, and F1 score against ground truth.

Usage:
    from tools.accuracy import calculate_accuracy
    results = calculate_accuracy(findings, ground_truth)
    print(results["summary"])
"""
import json
from typing import Optional


def calculate_accuracy(findings: list, ground_truth: list,
                       match_field: str = "ioc") -> dict:
    """
    Calculate precision, recall, and F1 score.

    Args:
        findings:     List of hypothesis dicts from PHANTOM (critical + medium)
        ground_truth: List of dicts with at least {ioc: str, malicious: bool}
        match_field:  Field to match on (default: "ioc")

    Returns:
        {
            "precision": float,
            "recall": float,
            "f1_score": float,
            "false_positive_rate": float,
            "true_positives": [str],
            "false_positives": [str],
            "false_negatives": [str],
            "true_negatives": [str],
            "grade": str,  # A+ through F
            "summary": str,
        }
    """
    # Extract ground truth IOCs
    gt_malicious = set()
    gt_benign = set()
    for gt in ground_truth:
        ioc = gt.get(match_field, gt.get("ioc", "")).lower()
        if gt.get("malicious", False):
            gt_malicious.add(ioc)
        else:
            gt_benign.add(ioc)

    # Extract PHANTOM findings (CRITICAL and MEDIUM only = "detected as malicious")
    detected = set()
    for f in findings:
        conf = f.get("confidence", "")
        if conf in ("CRITICAL", "MEDIUM"):
            detected.add(f.get(match_field, f.get("ioc", "")).lower())

    # Calculate metrics
    true_positives = detected & gt_malicious
    false_positives = detected - gt_malicious
    false_negatives = gt_malicious - detected
    true_negatives = gt_benign - detected

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    tn = len(true_negatives)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Grade
    if f1 >= 1.0 and fpr == 0:
        grade = "A+"
    elif f1 >= 0.9:
        grade = "A"
    elif f1 >= 0.8:
        grade = "B"
    elif f1 >= 0.7:
        grade = "C"
    elif f1 >= 0.5:
        grade = "D"
    else:
        grade = "F"

    # Summary
    summary = (
        f"Precision: {precision:.0%} | Recall: {recall:.0%} | "
        f"F1: {f1:.0%} | FPR: {fpr:.0%} | Grade: {grade}\n"
        f"  TP={tp} FP={fp} FN={fn} TN={tn}"
    )

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "true_positives": sorted(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "true_negatives": sorted(true_negatives),
        "grade": grade,
        "summary": summary,
    }


def validate_from_files(findings_json_path: str,
                         ground_truth_path: str) -> dict:
    """
    Convenience: load findings and ground truth from JSON files.
    """
    with open(findings_json_path) as f:
        report = json.load(f)

    with open(ground_truth_path) as f:
        ground_truth = json.load(f)

    # Extract findings from PHANTOM report format
    findings = report.get("findings", [])
    if not findings:
        # Try alternate format
        findings = (report.get("critical_findings", []) +
                    report.get("medium_findings", []) +
                    report.get("low_findings", []) +
                    report.get("cleared_findings", []))

    # Handle ground truth format variations
    if isinstance(ground_truth, dict):
        ground_truth = ground_truth.get("processes", ground_truth.get("iocs", []))

    return calculate_accuracy(findings, ground_truth)
