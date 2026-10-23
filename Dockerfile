# Deployment draft. Docker was not run on the authoring host; see docs/CALISAN_MIMARI.md.
FROM maven:3.9.11-eclipse-temurin-17 AS java-tools
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY safepatch ./safepatch
COPY scripts/serve.py ./scripts/serve.py
RUN useradd --uid 1000 --create-home app && mkdir -p /data && chown app:app /data
ENV DATA_ROOT=/data
USER app

FROM base AS worker1
CMD ["python", "scripts/serve.py", "worker1", "--host", "0.0.0.0"]

FROM base AS seeded
USER root
COPY samples ./samples
COPY scripts/seed.py ./scripts/seed.py
RUN python scripts/seed.py > /dev/null && mv /app/.runtime/repos-v3 /repos && chmod -R a-w /repos
ENV REPO_ROOT=/repos
USER app

FROM seeded AS verifier
CMD ["python", "scripts/serve.py", "worker2", "--host", "0.0.0.0"]

FROM seeded AS orchestrator
CMD ["python", "scripts/serve.py", "orchestrator", "--host", "0.0.0.0"]

FROM seeded AS runner
USER root
COPY --from=java-tools /opt/java/openjdk /opt/java/openjdk
COPY --from=java-tools /usr/share/maven /usr/share/maven
ENV JAVA_HOME=/opt/java/openjdk PATH=/opt/java/openjdk/bin:/usr/share/maven/bin:$PATH MAVEN_CACHE=/m2
RUN pip install --no-cache-dir semgrep==1.136.0 setuptools==80.9.0
COPY rules /rules
ENV RULES_FILE=/rules/java.yml
RUN cd /repos/sql-01 && mvn -B -ntp -Dmaven.repo.local=/m2 -DskipTests package && mvn -B -ntp -Dmaven.repo.local=/m2 -Dtest=BehaviorTest test && mvn -B -ntp -Dmaven.repo.local=/m2 org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:help && chmod -R a+rX /m2
USER app
CMD ["python", "scripts/serve.py", "runner", "--host", "0.0.0.0"]

FROM base AS deployer
USER root
COPY --from=java-tools /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk PATH=/opt/java/openjdk/bin:$PATH
USER app
CMD ["python", "scripts/serve.py", "deployer", "--host", "0.0.0.0"]
