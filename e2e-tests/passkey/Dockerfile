FROM opensearchproject/opensearch:latest

# Note: This is for testing purposes only
# The plugin version may not match the OpenSearch version exactly
# In production, versions must match

USER root

# Install unzip
RUN yum install -y unzip

# Copy our custom-built security plugin
COPY ../../build/distributions/opensearch-security-3.5.0.0-SNAPSHOT.zip /tmp/

# Extract and manually install the plugin to bypass version check
RUN cd /tmp && \
    mkdir -p opensearch-security && \
    cd opensearch-security && \
    unzip -q /tmp/opensearch-security-3.5.0.0-SNAPSHOT.zip && \
    cd /tmp && \
    rm -rf /usr/share/opensearch/plugins/opensearch-security && \
    mv opensearch-security /usr/share/opensearch/plugins/ && \
    rm opensearch-security-3.5.0.0-SNAPSHOT.zip

# Fix permissions
RUN chown -R opensearch:opensearch /usr/share/opensearch/plugins/opensearch-security

USER opensearch
