import os
import click
import json
from datetime import datetime
from pathlib import Path
import securefix.sast.bandit_scanner as bandit_scanner
import securefix.cve.scanner as cve_scanner
from securefix.models import ScanResult
from json_repair import repair_json
from securefix.remediation.corpus_builder import DocumentProcessor
from typing import List, Dict


@click.group()
def cli():
    """SecureFix - Static Application Security Testing with Smart Remediation"""
    pass


@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--dependencies', '-d', type=click.Path(exists=True),
              help='Path to requirements.txt or pyproject.toml for CVE scanning')
@click.option('--output', '-o', type=click.Path(), default='report.json',
              help='Output JSON file (default: report.json)')
@click.option('--severity', '-s', type=click.Choice(['low', 'medium', 'high'], case_sensitive=True),
              default='medium', help='Severity of findings to report')
@click.option('--confidence', type=click.Choice(['low', 'medium', 'high'], case_sensitive=True),
              default='medium', help='Confidence of findings to report')
def scan(target, dependencies, output, severity, confidence):
    """Scan TARGET (file or directory) for security vulnerabilities"""

    click.echo(f"Scanning {target}...")

    # SAST scanning
    target_path = Path(target)
    if target_path.is_file() or target_path.is_dir():
        sast_findings = bandit_scanner.scan(str(target_path), severity, confidence)
    else:
        click.echo(f"Error: {target} is not a valid file or directory", err=True)
        return

    click.echo(f"Found {len(sast_findings)} SAST findings")

    # CVE scanning (optional)
    cve_findings = []
    if dependencies:
        click.echo(f"Scanning dependencies in {dependencies}...")
        cve_findings = cve_scanner.scan_dependencies(dependencies)
        click.echo(f"Found {len(cve_findings)} vulnerable dependencies")

    # Create report
    scan_result = ScanResult(
        scan_timestamp=datetime.now().isoformat(),
        findings=sast_findings,
        cve_findings=cve_findings
    )

    # Write output
    with open(output, 'w') as f:
        json.dump(scan_result.to_dict(), f, indent=2)

    click.echo(f"\nReport saved to {output}")

    # Print summary
    summary = scan_result.to_dict()['summary']
    click.echo(f"\nSummary:")
    click.echo(f"  Total SAST findings: {summary['total_findings']}")
    click.echo(f"  Total CVE findings: {summary['total_cve_findings']}")
    click.echo(f"  By severity:")
    for severity, count in summary['by_severity'].items():
        if count > 0:
            click.echo(f"    {severity}: {count}")


@cli.command()
@click.option('--corpus-path', '-c', type=click.Path(),
              default='./remediation/corpus',
              help='Path to security corpus files')
@click.option('--rebuild', is_flag=True,
              help='Rebuild vector store even if one exists')
@click.option('--persist-dir', type=click.Path(),
              default='./chroma_db',
              help='Directory to store vector database')
def ingest(corpus_path, rebuild, persist_dir):
    """Build vector database from security corpus"""
    import time
    start_time = time.time()

    # Ensure corpus directory exists
    if not os.path.exists(corpus_path):
        click.echo(f"Creating corpus directory: {corpus_path}")
        os.makedirs(corpus_path, exist_ok=True)
        click.echo(f"Please add security corpus files and run again")
        click.echo(f"Supported formats: .csv, .md, .yaml, .yml")
        return

    # Check if already exists
    if os.path.exists(persist_dir) and not rebuild:
        click.echo(f"Vector database already exists at {persist_dir}")
        click.echo("Use --rebuild to recreate it")
        return

    # Clean up if rebuilding
    if os.path.exists(persist_dir) and rebuild:
        import shutil
        click.echo(f"Removing old database...")
        shutil.rmtree(persist_dir)

    # Initialize processor
    try:
        processor = DocumentProcessor(persist_directory=persist_dir)
    except Exception as e:
        click.echo(f"Failed to initialize: {e}", err=True)
        return

    # Process documents
    click.echo(f"Processing corpus from {corpus_path}...")
    click.echo("(This may take several minutes...)")

    processing_start = time.time()
    try:
        result = processor.process_documents(corpus_path)
    except Exception as e:
        click.echo(f"Failed to build vector database: {e}", err=True)
        return
    processing_time = time.time() - processing_start

    if result is None:
        click.echo("No documents were successfully processed", err=True)
        return

    vector_store, bm25_index, bm25_chunks = result

    total_time = time.time() - start_time

    # Show statistics
    click.echo(f"\nVector database built successfully!")
    click.echo(f"\nStatistics:")
    click.echo(f"  Chunks indexed: {len(bm25_chunks)}")
    click.echo(f"  Storage location: {persist_dir}")
    click.echo(f"  Corpus source: {corpus_path}")
    click.echo(f"\nPerformance:")
    click.echo(f"  Processing time: {processing_time:.2f}s")
    click.echo(f"  Total time: {total_time:.2f}s")
    click.echo(f"  Average: {processing_time / len(bm25_chunks) * 1000:.1f}ms per chunk")
    click.echo(f"\nReady to use with: securefix fix <report.json>")


@cli.command()
@click.argument('report', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), default='fixes.json',
              help='Output JSON file with remediation suggestions (default: fixes.json)')
@click.option('--interactive', '-i', is_flag=True,
              help='Review and apply fixes interactively')
@click.option('--llm-mode', type=click.Choice(['local', 'google', 'llamacpp'], case_sensitive=False),
              default='local', help='LLM backend to use (default: local)')
@click.option('--model-name', type=str,
              help='Override default model name (for ollama/google)')
@click.option('--model-path', type=click.Path(exists=True),
              help='Path to GGUF model file (for llamacpp mode)')
@click.option('--no-cache', is_flag=True,
              help='Disable semantic caching')
@click.option('--persist-dir', type=click.Path(),
              default='./chroma_db',
              help='Vector database directory (default: ./chroma_db)')
@click.option('--severity-filter', type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Only fix vulnerabilities of this severity or higher')
@click.option('--sast-only', is_flag=True,
              help='Only remediate SAST findings (skip CVE findings)')
@click.option('--cve-only', is_flag=True,
              help='Only remediate CVE findings (skip SAST findings)')
def fix(report, output, interactive, llm_mode, model_name, model_path, no_cache, persist_dir,
        severity_filter, sast_only, cve_only):
    """Generate security fixes for vulnerabilities in REPORT"""
    import time
    from securefix.remediation.corpus_builder import DocumentProcessor
    from securefix.remediation.fix_knowledge_store import DocumentStore
    from securefix.remediation.remediation_engine import RemediationEngine

    start_time = time.time()

    # Load scan report
    click.echo(f"Loading scan report from {report}...")
    try:
        with open(report, 'r') as f:
            scan_data = json.load(f)
    except json.JSONDecodeError:
        click.echo(f"Error: Invalid JSON in report file", err=True)
        return

    # Load findings based on flags
    sast_findings = scan_data.get('sast_findings', [])
    cve_findings = scan_data.get('cve_findings', [])

    if sast_only:
        findings = sast_findings
        click.echo(f"SAST only mode: {len(findings)} findings")
    elif cve_only:
        findings = cve_findings
        click.echo(f"CVE only mode: {len(findings)} findings")
    else:
        findings = sast_findings + cve_findings
        click.echo(f"Found {len(sast_findings)} SAST + {len(cve_findings)} CVE findings")

    if not findings:
        click.echo("No vulnerabilities found in report")
        return

    # Apply severity filter if specified
    if severity_filter:
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        min_severity = severity_order.get(severity_filter, 0)
        original_count = len(findings)
        findings = [f for f in findings
                    if severity_order.get(f.get('severity', 'low').lower(), 1) >= min_severity]
        click.echo(f"Filtered to {len(findings)}/{original_count} findings (>= {severity_filter})")

    if not findings:  # Check again after filtering
        click.echo("No vulnerabilities match the filter criteria")
        return

    click.echo(f"Processing {len(findings)} vulnerabilities")

    # Initialize remediation engine
    click.echo("\nInitializing remediation engine...")

    if not os.path.exists(persist_dir):
        click.echo(f"Error: Vector database not found at {persist_dir}", err=True)
        click.echo("Please run: securefix ingest", err=True)
        return

    try:
        processor = DocumentProcessor(persist_directory=persist_dir)
        vector_store, bm25_index, bm25_chunks = processor.load_existing_vectorstore()

        if vector_store is None:
            click.echo("Error: Failed to load vector database", err=True)
            click.echo("Please run: securefix ingest", err=True)
            return
    except Exception as e:
        click.echo(f"Error loading vector database: {e}", err=True)
        return

    try:
        llm_config = _configure_llm(llm_mode, model_name, model_path)
        if not llm_config:
            return
    except Exception as e:
        click.echo(f"Error configuring LLM: {e}", err=True)
        return

    try:
        document_store = DocumentStore(
            vector_store=vector_store,
            bm25_index=bm25_index,
            bm25_chunks=bm25_chunks
        )

        remediation_engine = RemediationEngine(
            document_store=document_store,
            llm_config=llm_config,
            enable_cache=not no_cache
        )

        click.echo(f"Using LLM: {remediation_engine.get_llm_info()}")
        if not no_cache:
            click.echo("Semantic caching enabled")
    except Exception as e:
        click.echo(f"Error initializing remediation engine: {e}", err=True)
        return

    # Process vulnerabilities
    click.echo(f"\nGenerating fixes for {len(findings)} vulnerabilities...")
    click.echo("(This may take several minutes...)\n")

    remediations = []
    success_count = 0
    failed_count = 0

    for i, finding in enumerate(findings, 1):
        # Check if it's a CVE finding or SAST finding
        if 'package' in finding:  # CVE finding
            vuln_type = f"Vulnerable Dependency: {finding.get('package')}"
            file_path = finding.get('file', 'requirements.txt')
            line_number = 'N/A'
            snippet = f"{finding.get('package')}=={finding.get('version')}\nCVEs: {', '.join(finding.get('cves', []))}"
        else:  # SAST finding
            vuln_type = finding.get('type', 'Unknown')
            file_path = str(finding.get('file', 'Unknown'))
            line_number = str(finding.get('line', 'Unknown'))
            snippet = finding.get('snippet', '')

        click.echo(f"[{i}/{len(findings)}] {vuln_type} at {file_path}:{line_number}")

        vulnerability = {
            'type': vuln_type,
            'snippet': snippet,
            'line_number': line_number,
            'file_path': file_path,
            'severity': finding.get('severity', 'High'),  # Default to High for CVEs
            'cwe_id': finding.get('cwe_id', ''),
        }

        try:
            result = remediation_engine.generate_fix(vulnerability)
            answer_text = result.get('answer', '')
            fix_data = _parse_fix_response(answer_text)

            if fix_data:
                remediation = {
                    'finding': finding,
                    'suggested_fix': fix_data.get('suggested_fix', ''),
                    'explanation': fix_data.get('explanation', ''),
                    'confidence': fix_data.get('confidence', 'Unknown'),
                    'cwe_id': fix_data.get('cwe_id', ''),
                    'source_documents': [
                        {
                            'source': doc.metadata.get('source', 'Unknown'),
                            'doc_type': doc.metadata.get('doc_type', 'Unknown')
                        }
                        for doc in result.get('source_documents', [])
                    ]
                }
                remediations.append(remediation)
                success_count += 1
                click.echo(f"  Success (Confidence: {fix_data.get('confidence', 'Unknown')})")
            else:
                click.echo(f"  Warning: Could not parse fix response", err=True)
                failed_count += 1

        except Exception as e:
            click.echo(f"  Error: {e}", err=True)
            failed_count += 1
            continue

    # Interactive mode
    if interactive and remediations:
        click.echo("\n" + "=" * 70)
        click.echo("INTERACTIVE REVIEW MODE")
        click.echo("=" * 70 + "\n")
        remediations = _interactive_review(remediations)

    # Save results
    output_data = {
        'summary': {
            'scan_timestamp': scan_data.get('summary', {}).get('scan_timestamp'),
            'remediation_timestamp': datetime.now().isoformat(),
            'llm_info': remediation_engine.get_llm_info(),
            'total_findings': len(findings),
            'sast_findings_count': len([r for r in remediations if _is_sast_finding(r['finding'], sast_findings)]),
            'cve_findings_count': len([r for r in remediations if not _is_sast_finding(r['finding'], sast_findings)]),
            'successful_remediations': success_count,
            'failed_remediations': failed_count,
            'by_severity': _count_by_severity(remediations),
            'by_confidence': _count_by_confidence(remediations)
        },
        'remediations': remediations
    }

    with open(output, 'w') as f:
        json.dump(output_data, f, indent=2)

    total_time = time.time() - start_time

    # Print summary
    click.echo(f"\n{'=' * 70}")
    click.echo("REMEDIATION SUMMARY")
    click.echo("=" * 70)
    click.echo(f"Total vulnerabilities: {len(findings)}")
    click.echo(f"Successfully remediated: {success_count}")
    click.echo(f"Failed: {failed_count}")
    click.echo(f"\nBy confidence:")
    for conf, count in output_data['summary']['by_confidence'].items():
        if count > 0:
            click.echo(f"  {conf}: {count}")
    click.echo(f"\nProcessing time: {total_time:.2f}s")
    click.echo(f"Average: {total_time / len(findings):.2f}s per vulnerability")
    click.echo(f"\nResults saved to: {output}")


def _configure_llm(mode: str, model_name: str = None, model_path: str = None):
    """Configure LLM based on mode and validate availability."""
    from securefix.remediation.llm import (
        LLMFactory,
        LLAMACPP_AVAILABLE,
        check_ollama_available,
        check_google_api_key,
        check_llamacpp_available,
        validate_gguf_model,
    )
    from securefix.remediation.config import app_config

    if mode == 'local':
        if not check_ollama_available():
            click.echo("Error: Ollama is not available", err=True)
            click.echo("Please install Ollama: https://ollama.com/", err=True)
            return None

        model = model_name or app_config.config.model_name or "llama3.2:3b"
        return LLMFactory.create_ollama(model_name=model)

    elif mode == 'google':
        api_key = app_config.config.google_api_key
        if not api_key:
            click.echo("Error: GOOGLE_API_KEY not set", err=True)
            click.echo("Set it in .env or environment", err=True)
            return None

        if not check_google_api_key(api_key):
            click.echo("Error: Invalid Google API key", err=True)
            return None

        model = model_name or app_config.config.model_name or "gemini-2.0-flash-lite"
        return LLMFactory.create_google(api_key=api_key, model_name=model)

    elif mode == 'llamacpp':
        if not LLAMACPP_AVAILABLE:
            click.echo("Error: llama-cpp-python is not installed", err=True)
            click.echo("Install with: pip install securefix[llamacpp]", err=True)
            return None

        # Get model path from CLI arg, env var, or config
        model_file = model_path or app_config.config.llama_cpp_model_path

        if not model_file:
            click.echo("Error: Model path not specified", err=True)
            click.echo("Use --model-path or set LLAMACPP_MODEL_PATH environment variable", err=True)
            return None

        # Validate the model file
        is_valid, error_msg = validate_gguf_model(model_file)

        if not is_valid:
            click.echo(f"Error: {error_msg}", err=True)
            click.echo("Download GGUF models from: https://huggingface.co/models?library=gguf", err=True)
            return None

        # Create config using settings from app_config
        return LLMFactory.create_llamacpp(
            model_path=model_file,
            n_ctx=app_config.config.llama_cpp_n_ctx,
            n_threads=app_config.config.llama_cpp_n_threads,
            n_gpu_layers=app_config.config.llama_cpp_n_gpu_layers,
            n_batch=app_config.config.llama_cpp_n_batch,
        )

    return None


def _parse_fix_response(response: str) -> dict:
    """Parse LLM JSON response, handling common formatting issues."""
    if not response:
        return None

    # Remove markdown code blocks
    if '```json' in response:
        start_marker = response.find('```json')
        if start_marker != -1:
            start = start_marker + 7
            end = response.rfind('```')
            if end != -1 and end > start:
                response = response[start:end].strip()
    elif response.startswith('```') and response.count('```') >= 2:
        start = response.find('```') + 3
        end = response.rfind('```')
        if end != -1 and end > start:
            response = response[start:end].strip()

    response = response.strip()

    # Try direct parse first
    try:
        data = json.loads(response)

        # Handle if LLM returns a list instead of dict
        if isinstance(data, list):
            if len(data) > 0 and isinstance(data[0], dict):
                return data[0]  # Take first dict from list
            else:
                return None

        return data if isinstance(data, dict) else None

    except json.JSONDecodeError:
        # Use json-repair for messy LLM output
        try:
            repaired = repair_json(response)
            data = json.loads(repaired)

            # Handle list here too
            if isinstance(data, list):
                if len(data) > 0 and isinstance(data[0], dict):
                    return data[0]
                else:
                    return None

            return data if isinstance(data, dict) else None

        except Exception as e:
            click.echo(f"  Warning: Could not parse fix response: {e}", err=True)
            return None


def _interactive_review(remediations: List[Dict]) -> List[Dict]:
    """Allow user to review and filter fixes interactively."""
    approved = []

    for i, rem in enumerate(remediations, 1):
        finding = rem['finding']
        click.echo(f"\n{'-' * 70}")
        click.echo(f"Fix {i}/{len(remediations)}")
        click.echo(f"{'-' * 70}")
        click.echo(f"Type: {finding.get('type')}")
        click.echo(f"File: {finding.get('file')}:{finding.get('line')}")
        click.echo(f"Severity: {finding.get('severity')}")
        click.echo(f"Confidence: {rem.get('confidence')}")
        click.echo(f"\nExplanation:")
        click.echo(f"{rem.get('explanation')}")
        click.echo(f"\nSuggested Fix:")
        click.echo(f"{rem.get('suggested_fix')}")

        choice = click.prompt(
            '\nAccept this fix? [y]es / [n]o / [q]uit',
            type=click.Choice(['y', 'n', 'q'], case_sensitive=False),
            default='y'
        )

        if choice == 'q':
            click.echo("Exiting interactive review...")
            break
        elif choice == 'y':
            approved.append(rem)
            click.echo("Fix approved")
        else:
            click.echo("Fix rejected")

    click.echo(f"\nApproved {len(approved)}/{len(remediations)} fixes")
    return approved


def _count_by_severity(remediations: List[Dict]) -> Dict[str, int]:
    """Count remediations by severity."""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for rem in remediations:
        severity = rem['finding'].get('severity', 'medium').lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _count_by_confidence(remediations: List[Dict]) -> Dict[str, int]:
    """Count remediations by confidence level."""
    counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for rem in remediations:
        confidence = rem.get('confidence', 'Medium')
        counts[confidence] = counts.get(confidence, 0) + 1
    return counts


def _is_sast_finding(finding: Dict, sast_findings: List[Dict]) -> bool:
    """Check if finding is from SAST scan (vs CVE scan)."""
    return finding in sast_findings


if __name__ == '__main__':
    cli()