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
MkDocs hook to copy proposal files from docs/proposals to site-src/proposals
for inclusion in the documentation site.

This allows proposals to be managed in docs/proposals while being served
as part of the documentation.
"""

import logging
from mkdocs import plugins
from mkdocs.structure.files import File
from pathlib import Path

log = logging.getLogger(f'mkdocs.plugins.{__name__}')


@plugins.event_priority(100)
def on_files(files, config, **kwargs):
    """
    MkDocs hook that runs when files are loaded.
    Copies proposal files from docs/proposals to the site.
    """
    log.info("Adding proposals to site")

    # Check if site-src/proposals exists (files copied out-of-band from MkDocs)
    site_src_proposals = Path('site-src/proposals')

    # Files to preserve in site-src/proposals (should not be deleted)
    preserve_files = {'overview.md', '.pages', 'README.md'}

    if site_src_proposals.exists() and site_src_proposals.is_dir():
        log.info("Found site-src/proposals/ directory. Cleaning up auto-copied files...")

        # Only clean up files in the root of site-src/proposals/
        # Don't recurse into subdirectories like landing/
        for item in site_src_proposals.iterdir():
            if item.is_file() and item.name not in preserve_files:
                # This is an auto-copied proposal file, remove it
                path = '/'.join(item.parts[1:])  # e.g., proposals/0008-ToolAuthAPI.md

                existing_file = files.get_file_from_path(path)
                if existing_file:
                    files.remove(existing_file)

                # Delete the auto-copied file from filesystem
                if item.exists():
                    item.unlink()
                    log.debug(f"Deleted auto-copied file: {item}")
            else:
                log.debug(f"Preserving {item.name}")

    # Path to source proposals
    proposals_src = Path('docs/proposals')

    if not proposals_src.exists():
        log.warning("docs/proposals directory not found, skipping proposal copy")
        return files

    # Iterate over proposal files and add them to the site
    # Only process .md files that match the proposal naming pattern (NNNN-*.md)
    for proposal_file in proposals_src.glob('*.md'):
        filename = proposal_file.name

        # Skip README.md and files that don't start with a digit
        if filename == 'README.md' or not filename[0].isdigit():
            log.debug(f"Skipping file: {filename}")
        else:
            file_path = f'proposals/{filename}'

            if files.get_file_from_path(file_path) is None:
                new_file = File(
                    path=file_path,
                    src_dir='docs/',
                    dest_dir=config['site_dir'],
                    use_directory_urls=config['use_directory_urls']
                )

                files.append(new_file)
                log.debug(f"Added proposal file: {file_path}")

    # Add landing pages from site-src/proposals/landing/
    landing_dir = Path('site-src/proposals/landing')
    log.info(f"Looking for landing pages in {landing_dir}")
    if landing_dir.exists():
        log.info(f"Landing directory exists")
        landing_files = list(landing_dir.glob('*.md'))
        log.info(f"Found {len(landing_files)} landing files: {[f.name for f in landing_files]}")
        for landing_file in landing_files:
            file_path = f'proposals/landing/{landing_file.name}'
            log.info(f"Processing landing file: {file_path}")

            existing = files.get_file_from_path(file_path)
            if existing is None:
                new_file = File(
                    path=file_path,
                    src_dir='site-src/',
                    dest_dir=config['site_dir'],
                    use_directory_urls=config['use_directory_urls']
                )

                files.append(new_file)
                log.info(f"✓ Added landing page: {file_path}")
            else:
                log.info(f"Landing page already exists: {file_path}")
    else:
        log.warning(f"Landing directory does not exist: {landing_dir}")

    log.info(f"Finished adding proposals to site")
    return files
