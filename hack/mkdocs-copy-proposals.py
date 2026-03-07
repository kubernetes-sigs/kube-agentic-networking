#!/usr/bin/env python3

# Copyright 2024 The Kubernetes Authors.
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

import shutil
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
    if site_src_proposals.exists() and site_src_proposals.is_dir():
        log.info("Found site-src/proposals/ directory. Cleaning up...")

        # Iterate over the list of files in this directory and remove them from MkDocs
        for root_dir, _, proposal_files in site_src_proposals.walk():
            for filename in proposal_files:
                # Exclude the leading 'site-src/' to get the relative path as it
                # exists on the site (i.e., proposals/overview.md)
                path = '/'.join(root_dir.parts[1:])

                existing_file = files.get_file_from_path(f'{path}/{filename}')
                if existing_file:
                    files.remove(existing_file)

        # Delete the 'site-src/proposals' directory
        shutil.rmtree(site_src_proposals)

    # Path to source proposals
    proposals_src = Path('docs/proposals')

    if not proposals_src.exists():
        log.warning("docs/proposals directory not found, skipping proposal copy")
        return files

    # Iterate over all the files in the proposals folder and add them to the site
    for root_dir, _, proposal_files in proposals_src.walk():
        for filename in proposal_files:
            # Skip README.md in the root proposals directory
            if filename == 'README.md' and root_dir == proposals_src:
                continue

            # Calculate relative path from docs/proposals
            relative_path = root_dir.relative_to('docs')
            file_path = str(relative_path / filename)

            if files.get_file_from_path(file_path) is None:
                new_file = File(
                    path=file_path,
                    src_dir='docs/',
                    dest_dir=config['site_dir'],
                    use_directory_urls=config['use_directory_urls']
                )

                files.append(new_file)
                log.debug(f"Added proposal file: {file_path}")

    log.info(f"Finished adding proposals to site")
    return files
