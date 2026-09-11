"""Módulo de Parsing.

Lê um arquivo de log linha a linha e converte cada linha relevante em um
evento estruturado de autenticação SSH (timestamp, hostname, pid, tipo de
evento, usuário, IP de origem, porta). Não sabe nada sobre regras de
detecção.

Implementação prevista na Fase 1.
"""
