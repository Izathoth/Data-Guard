import os
import base64
import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score


class CriptografadorDeArquivo:
    def __init__(self, senha: str):
        self.chave, self.salt = self._gerar_chave(senha)

    def _gerar_chave(self, senha: str) -> tuple:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        chave = base64.urlsafe_b64encode(kdf.derive(senha.encode()))
        return chave, salt

    def criptografar_arquivo(self, caminho_arquivo: str) -> None:
        fernet = Fernet(self.chave)
        with open(caminho_arquivo, 'rb') as arquivo:
            dados = arquivo.read()
        dados_criptografados = fernet.encrypt(dados)
        with open(caminho_arquivo, 'wb') as arquivo_criptografado:
            arquivo_criptografado.write(self.salt + dados_criptografados)
        print(f"Arquivo criptografado: {caminho_arquivo}")


class AnalisadorDeDados:
    def __init__(self, dados: pd.DataFrame):
        self.dados = dados

    def analisar(self) -> None:
        X = self.dados.drop('classe', axis=1)
        y = self.dados['classe']
        X_treino, X_teste, y_treino, y_teste = train_test_split(X, y, test_size=0.2, random_state=42)

        modelo = GradientBoostingClassifier()
        modelo.fit(X_treino, y_treino)

        previsoes = modelo.predict(X_teste)
        precisao = accuracy_score(y_teste, previsoes)
        print(f"Precisão do modelo: {precisao:.2f}")


def main() -> None:
    senha = input("Digite a senha para criptografia: ").strip()
    criptografador = CriptografadorDeArquivo(senha)
    
    arquivo_para_criptografar = 'dados.txt'
    if os.path.exists(arquivo_para_criptografar):
        criptografador.criptografar_arquivo(arquivo_para_criptografar)
    else:
        print(f"Arquivo não encontrado: {arquivo_para_criptografar}")
        return

    try:
        dados = pd.read_csv('dados.csv')
        analisador = AnalisadorDeDados(dados)
        analisador.analisar()
    except FileNotFoundError:
        print("Arquivo de dados não encontrado: dados.csv")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")


if __name__ == "__main__":
    main()