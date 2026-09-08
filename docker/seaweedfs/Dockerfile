FROM chrislusf/seaweedfs@sha256:52194fba4fecd0083c842158b3a902ba6e04a63619b2b0efcd08007bdb6a4602

USER root
RUN mkdir -p /run/tracebed-s3 /data \
 && chown -R 65532:65532 /run/tracebed-s3 /data

COPY --chmod=0555 docker/seaweedfs/entrypoint.sh /usr/local/bin/tracebed-seaweed-entrypoint

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tracebed-seaweed-entrypoint"]
