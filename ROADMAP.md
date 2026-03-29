# NetWatch — Roadmap de Atualizações Futuras

> Documento vivo que registra melhorias planejadas, bugs identificados e próximos passos do projeto.

---

## 🗓️ Versão Atual

**Status:** Em desenvolvimento ativo  
**Última revisão:** 2026-03-29

---

## 🔴 Correções Críticas (Alta Prioridade)

Bugs que afetam o comportamento correto da ferramenta.

### 1. Double port scan em `devices.py`
- **Onde:** `add_device()` + `identify_device()` (linhas ~447–458)
- **Problema:** `identify_device()` já chama `scan_ports()` internamente, mas `add_device()` chama novamente no bloco fallback. Cada host sem vendor recebe **2 port scans** desnecessários, dobrando o tempo de scan.
- **Solução:** Remover o bloco fallback de `scan_ports()` dentro de `add_device()` e reutilizar o resultado de `identify_device()`.

### 2. Race condition no contador de tráfego (`bandwidth.py`)
- **Onde:** `_traffic` global + `get_traffic_per_device()` (linha ~34)
- **Problema:** `_traffic` é sobrescrito com um novo `defaultdict` sem lock, enquanto `_packet_handler` (thread separada) pode estar escrevendo nele simultaneamente → perda silenciosa de dados de tráfego.
- **Solução:** Adicionar `threading.Lock` protegendo leitura e reset de `_traffic`.

### 3. Threads de spoofing se acumulam (`spoof.py`)
- **Onde:** `start_spoofing()` (linha ~38)
- **Problema:** A cada refresh de dispositivos (a cada 10s no `main.py`), uma nova thread de spoofing é criada sem parar a anterior, causando threads zumbis e pacotes ARP duplicados.
- **Solução:** Usar `threading.Event` para sinalizar parada à thread anterior antes de criar uma nova.

### 4. Gateway hardcoded (`main.py`)
- **Onde:** `status()` (linha 65)
- **Problema:** `gateway_ip = "192.168.100.1"` funciona apenas nessa rede específica. Em outras redes, o spoofing falha silenciosamente.
- **Solução:** Detectar o gateway automaticamente via tabela de roteamento do sistema.

### 5. `ping_scan()` serial e com payload incorreto (`devices.py`)
- **Onde:** `ping_scan()` (linhas ~215–238)
- **Problema:** Os pings são enviados um a um (sem concorrência) e o payload ICMP é mal-formado (não é um Echo Request válido), tornando a função lenta e pouco confiável.
- **Solução:** Paralelizar via `ThreadPoolExecutor` e corrigir o pacote ICMP.

---

## 🟡 Otimizações de Performance (Média Prioridade)

Melhorias que reduzem tempo de execução significativamente.

### 6. Identificação de dispositivos sequencial (`devices.py`)
- **Onde:** `scan_devices()` → `add_device()` para cada host
- **Problema:** Com 20+ dispositivos, o scan de portas e identificação de vendor rodam um por um, tornando o scan total extremamente lento.
- **Solução:** Usar `concurrent.futures.ThreadPoolExecutor` para processar múltiplos hosts em paralelo.

### 7. `scan_ports()` serial porta a porta (`devices.py`)
- **Onde:** `scan_ports()` (linhas ~241–265)
- **Problema:** Cada porta é testada abrindo um socket, aguardando timeout e fechando sequencialmente. Com 40+ portas e timeout de 0.5s, um único host pode levar ~20s.
- **Solução:** Paralelizar abertura de sockets com `ThreadPoolExecutor`.

### 8. `get_bandwidth()` bloqueante (`bandwidth.py`)
- **Onde:** `get_bandwidth()` (linha ~43)
- **Problema:** Chama `time.sleep(1)` a cada invocação, incluindo dentro do loop do `monitor` e do `build_layout` no modo `-t`, travando o render por 1 segundo a cada atualização.
- **Solução:** Manter snapshot anterior em memória e calcular delta sem sleep, ou usar contadores do modo sniff já ativo.

### 9. `import glob` duplicado (`devices.py`)
- **Onde:** Linha 8 (top-level) e linha 174 (dentro de função)
- **Problema:** Import redundante dentro da função — não afeta funcionalidade, mas é código desnecessário.
- **Solução:** Remover o import interno da função.

### 10. `get_if_hwaddr()` chamado por pacote (`spoof.py`)
- **Onde:** `spoof()` (linha ~22)
- **Problema:** `get_if_hwaddr()` é chamado a cada pacote ARP enviado (a cada 2s para cada target), sendo uma syscall desnecessariamente repetida.
- **Solução:** Cachear o MAC da interface no início do `start_spoofing()` e reutilizar.

---

## 🟢 Qualidade de Código (Baixa Prioridade)

Melhorias que aumentam legibilidade e manutenibilidade.

### 11. Globais sem encapsulamento (`bandwidth.py`)
- `_traffic` e `_local_ip` são globais mutáveis sem qualquer encapsulamento.
- **Solução:** Encapsular em uma classe `BandwidthMonitor` com métodos claros.

### 12. Condição `if len(parts) >= 3` duplicada (`devices.py:189`)
- Há um `if len(parts) >= 3` dentro de outro `if len(parts) >= 3` identico.
- **Solução:** Remover a checagem interna redundante.

### 13. Magic number `addr.family == 2`
- **Onde:** `main.py:68`, `devices.py:85`, `devices.py:99`, `devices.py:476`
- O número `2` representa `socket.AF_INET` mas não é óbvio para quem lê.
- **Solução:** Substituir por `import socket; socket.AF_INET`.

### 14. `requirements.txt` vazio
- O arquivo existe mas está vazio. Dificulta instalação do projeto por terceiros.
- **Solução:** Preencher com as dependências reais: `scapy`, `psutil`, `python-nmap`, `mac-vendor-lookup`, `rich`, `typer`.

### 15. `get_os()` definida mas nunca chamada
- **Onde:** `devices.py:294`
- A função realiza um scan nmap completo mas não é chamada em nenhum ponto do fluxo atual.
- **Solução:** Integrar ao fluxo via flag `--os-detect`, ou remover para reduzir código morto.

---

## 🚀 Funcionalidades Futuras (Backlog)

Ideias e melhorias além das correções actuais.

- [ ] **Exportar resultados** para JSON/CSV (`netwatch scan --output devices.json`)
- [ ] **Alertas de novos dispositivos** — notificar quando um dispositivo desconhecido entra na rede
- [ ] **Histórico de dispositivos** — persistir lista de devices conhecidos em disco
- [ ] **Filtros por tipo** — `netwatch scan --filter windows` / `--filter iot`
- [ ] **Relatório HTML** — gerar relatório visual dos dispositivos encontrados
- [ ] **Suporte IPv6** — detectar dispositivos em redes dual-stack
- [ ] **Modo daemon** — rodar em background e expor métricas via HTTP (Prometheus/Grafana)
- [ ] **Testes automatizados** — cobertura de unit tests para os módulos `devices`, `bandwidth` e `spoof`
- [ ] **Detecção de SO via TTL** — inferir OS pelo valor TTL das respostas ICMP (Linux=64, Windows=128)

---

## 📋 Changelog

### 2026-03-29
- Revisão completa do código — identificados 15 pontos de melhoria (5 críticos, 5 performance, 5 qualidade)
- Criado este documento de roadmap
