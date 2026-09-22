python3 - <<'PYEOF'
import subprocess
rule = (
 "Complemento da ERR-0039, que trata do caso irmao. A contaminacao nao e da ACAO (matar), e do "
 "PREDICADO: qualquer pgrep -f, pkill -f ou ps canalizado para grep com um padrao, disparado de "
 "dentro de uma sessao de ferramenta, inclui o proprio shell — porque o padrao esta na argv dele. "
 "Vale para MATAR, para ESPERAR e para so CHECAR. "
 "E o modo de falha da espera e PIOR que o do kill: matar a si mesmo devolve exit 143/144 e chama "
 "atencao, enquanto um until/while que casa a si mesmo trava para sempre, e a saida e visualmente "
 "identica a \"o job ainda esta rodando\" — ninguem suspeita do laco, so do job. "
 "Teste antes de escrever qualquer laco de espera: rode o pgrep SOZINHO com o alvo comprovadamente "
 "morto e exija saida VAZIA. Se voltar uma linha, o padrao esta errado, nao o sistema. "
 "Correcoes em ordem de robustez: (1) capture o PID uma vez e espere por ele com kill -0 sobre esse "
 "PID concreto, que nao tem como casar voce; (2) espere por um ARTEFATO em vez de por um processo — "
 "arquivo de saida, linha no log, marcador que o job escreve ao terminar — que alem de imune ainda "
 "cobre o caso de o processo morrer sem completar; (3) se insistir no padrao, ancore num fragmento "
 "que so o alvo tem, como o interpretador mais o caminho do script, nunca so o nome do script."
)
cause = (
 "Escrevi um laco de espera em background usando until com pgrep -f sobre o nome do script. O padrao "
 "esta na argv do proprio shell que roda o pgrep, entao ele acha a si mesmo, sempre sai 0, o ! inverte "
 "para falso e o until NUNCA satisfaz — laco infinito mesmo com o alvo morto havia horas, ate o usuario "
 "matar a tarefa. O agravante: minutos antes, na mesma sessao, usei pgrep -f com o mesmo padrao para "
 "CHECAR se o processo vivia, recebi 'ainda vivo' com ele morto, e escrevi na resposta que era a "
 "armadilha da ERR-0039 — reconheci o mecanismo e o reproduzi em seguida noutra forma. Razao: memorizei "
 "a ERR-0039 como regra de ACAO (nao use pkill -f) em vez de regra de PREDICADO, entao quando a acao "
 "mudou de matar para esperar a regra nao disparou."
)
subprocess.run([
 "python3", "/home/w-jr/.claude/plugins/cache/my-error-local/my-error/0.4.5/scripts/my_error.py",
 "learn", "--scope", "global", "--confidence", "0.92",
 "--tags", "pgrep,espera,laco-infinito,ERR-0039",
 "--title", "Casamento por linha de comando contamina ESPERA tambem, nao so kill",
 "--cause", cause, "--rule", rule,
], check=True)
PYEOF