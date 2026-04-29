#!/usr/bin/env python3

# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Generate landing pages for proposals organized by status.

Parses proposal markdown files from docs/proposals/, extracts metadata
(status, title), and generates status-specific landing pages
in site-src/proposals/landing/.

Can be used as an MkDocs hook or run standalone.
"""

import re
import logging
from pathlib import Path
from collections import defaultdict

log = logging.getLogger(f'mkdocs.plugins.{__name__}')

# Status order for navigation
STATUS_ORDER = [
    'Standard',
    'Completed',
    'Experimental',
    'Implementable',
    'Provisional',
    'Deferred',
    'Declined',
    'Withdrawn',
]


def parse_proposal_metadata(file_path):
    """
    Extract metadata from proposal markdown file.

    Expected format at top of file:
    Status: <status>
    # Title
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    metadata = {}

    # Extract number from filename (e.g., 0008-ToolAuthAPI.md -> 0008)
    match = re.match(r'(\d+)-(.+)\.md$', file_path.name)
    if match:
        metadata['number'] = match.group(1)
        metadata['slug'] = match.group(2)
    else:
        log.warning(f"Skipping {file_path.name}: doesn't match number-title.md format")
        return None

    # Extract status from metadata line
    status_match = re.search(r'Status:\s*(\w+)', content, re.IGNORECASE)
    if status_match:
        metadata['status'] = status_match.group(1)
    else:
        log.warning(f"No status found in {file_path.name}, skipping")
        return None

    # Extract title from first # heading
    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if title_match:
        metadata['title'] = title_match.group(1).strip()
    else:
        # Fallback to slug
        metadata['title'] = metadata['slug'].replace('-', ' ')

    return metadata


def generate_landing_page(status, proposals, output_dir):
    """Generate a landing page for proposals with the given status."""

    # Sort proposals by number
    proposals.sort(key=lambda p: p['number'])

    content = f"# {status} Proposals\n\n"

    if proposals:
        for proposal in proposals:
            # Simple list: just number and title linked
            content += f"- [{proposal['number']} - {proposal['title']}](../{proposal['number']}-{proposal['slug']}.md)\n"
    else:
        content += f"No {status.lower()} proposals at this time.\n"

    output_file = output_dir / f"{status.lower()}.md"
    output_file.write_text(content, encoding='utf-8')
    log.info(f"Generated {output_file}")


def generate_list_page(proposals_by_status, output_dir):
    """Generate a list page with all proposals organized by status."""

    content = "# All Proposals by Status\n\n"

    for status in STATUS_ORDER:
        if status in proposals_by_status and proposals_by_status[status]:
            proposals = sorted(proposals_by_status[status], key=lambda p: p['number'])
            content += f"## {status}\n\n"

            for proposal in proposals:
                # Simple list: just number and title linked
                content += f"- [{proposal['number']} - {proposal['title']}](../{proposal['number']}-{proposal['slug']}.md)\n"

            content += "\n"

    output_file = output_dir / "list.md"
    output_file.write_text(content, encoding='utf-8')
    log.info(f"Generated {output_file}")


def generate_all_landing_pages():
    """Generate all landing pages from proposals."""
    # Paths
    proposals_dir = Path('docs/proposals')
    output_dir = Path('site-src/proposals/landing')

    if not proposals_dir.exists():
        log.error(f"Proposals directory {proposals_dir} does not exist")
        return 1

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Parse all proposals
    proposals_by_status = defaultdict(list)

    for proposal_file in proposals_dir.glob('*.md'):
        # Skip README.md
        if proposal_file.name == 'README.md':
            log.debug(f"Skipping {proposal_file.name}")
        else:
            metadata = parse_proposal_metadata(proposal_file)
            if metadata:
                proposals_by_status[metadata['status']].append(metadata)
                log.debug(f"Parsed {proposal_file.name}: {metadata['status']}")

    if not proposals_by_status:
        log.warning("No proposals found")
        return 0

    # Generate landing pages for each status
    for status in STATUS_ORDER:
        if status in proposals_by_status:
            generate_landing_page(status, proposals_by_status[status], output_dir)

    # Generate the list page
    generate_list_page(proposals_by_status, output_dir)

    log.info(f"Generated {len(proposals_by_status)} status landing pages")
    return 0


def on_pre_build(config, **kwargs):
    """MkDocs hook that runs before the build starts."""
    log.info("Generating proposal landing pages...")
    generate_all_landing_pages()


def main():
    """Standalone execution."""
    logging.basicConfig(level=logging.INFO)
    return generate_all_landing_pages()


if __name__ == '__main__':
    exit(main())
