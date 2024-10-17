
 // Definindo as opções do jogo
const choices = ['pedra', 'papel', 'tesoura'];

// Obtendo referências aos botões e ao elemento de resultado
const rockButton = document.getElementById('rock') as HTMLButtonElement;
const paperButton = document.getElementById('paper') as HTMLButtonElement;
const scissorsButton = document.getElementById('scissors') as HTMLButtonElement;
const resultDisplay = document.getElementById('result') as HTMLDivElement;

// Função para determinar o vencedor
function determineWinner(playerChoice: string, computerChoice: string): string {
    if (playerChoice === computerChoice) {
        return "Empate!";
    } else if (
        (playerChoice === 'pedra' && computerChoice === 'tesoura') ||
        (playerChoice === 'papel' && computerChoice === 'pedra') ||
        (playerChoice === 'tesoura' && computerChoice === 'papel')
    ) {
        return "Você ganhou!";
    } else {
        return "Você perdeu!";
    }
}

// Função para jogar
function playGame(playerChoice: string) {
    const computerChoice = choices[Math.floor(Math.random() * choices.length)];
    const result = determineWinner(playerChoice, computerChoice);
    resultDisplay.textContent = `Você escolheu ${playerChoice}. A máquina escolheu ${computerChoice}. ${result}`;
}

// Adicionando eventos de clique aos botões
rockButton.addEventListener('click', () => playGame('pedra'));
paperButton.addEventListener('click', () => playGame('papel'));
scissorsButton.addEventListener('click', () => playGame('tesoura'));