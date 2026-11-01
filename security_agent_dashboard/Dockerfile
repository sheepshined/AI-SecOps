# AI SecOps 智能体平台
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py db.py llm_client.py xdr_pipeline.py skills.py \
     knowledge_context.py vuln_updater.py vuln_scheduler.py \
     vuln_stats_skill.py start_server.py ./
COPY templates/ templates/
COPY static/css/ static/css/
COPY static/js/ static/js/
COPY static/data/ static/data/

# XDR 自签证书环境
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# 生产建议：gunicorn -w 4 -b 0.0.0.0:5000 app:app
CMD ["python", "app.py"]
