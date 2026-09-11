"""Módulo de Regras (engine de detecção).

Recebe a lista de eventos estruturados produzida pelo parsing e aplica as
regras de detecção (força bruta no MVP; scanning e comprometimento como
extras), produzindo uma lista de alertas. Não sabe nada sobre formato de
arquivo nem sobre como o relatório será exibido.

Parâmetros das regras (limiar, janela de tempo) devem ficar nomeados e
ajustáveis num único lugar, não como números mágicos espalhados.

Implementação prevista na Fase 2 (RD1) e Fase 5 extra (RD2).
"""
