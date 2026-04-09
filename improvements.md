# Authentication

Update authentication such that users can own particular registry entries and set the visibility.

Unauthenticated users can see all public images in the app.

# Home Page

Current home page is more like an admin metrics page. I'd like a home page that is more public facing. Open to ideas.

# Artifacts page

Generally throughout the app we should default to amd64. From the page for a particular artifact, if I click the version it takes me to the build history for that version. It should instead take me to the sbom page and default to amd64.

Also provide a changelog type page for the build history of a particular version.

Revision links should take me to a particular commit if possible.

Licenses should appear at the SBOM level rather than the artifact level.

# Components page

Default sort by found in.

For a particular component - collapse the sboms under each image by default.

# Other

Enable scanning all images in a registry rather than just tagged. Since so much of ocidex function off of annotations and labels this will enable better build history
