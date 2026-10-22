# 0001. Architekturentscheidungen als ADRs dokumentieren

- **Status:** akzeptiert
- **Ticket:** –

## Kontext
Das Projekt wird von einer agentenbasierten Software-Fabrik entwickelt. Entscheidungen müssen für Menschen und Agenten
nachvollziehbar und versioniert sein.

## Entscheidung
Wesentliche Architekturentscheidungen werden als Architecture Decision Records in `docs/adr/` nach `template.md`
festgehalten, fortlaufend nummeriert und per Pull Request eingebracht.

## Konsequenzen
Entscheidungen sind im Code-Review sichtbar und mit Jira-Tickets verknüpft. Abgelöste ADRs bleiben erhalten.
