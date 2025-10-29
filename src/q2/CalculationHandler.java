package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class CalculationHandler implements Runnable {

    private final Socket socket;
    private final byte[] sharedKey;

    public CalculationHandler(Socket socket, byte[] key) {
        this.socket = socket;
        this.sharedKey = key;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String receivedLine = in.readLine();
            if (receivedLine == null) return;

            System.out.println("[CalcHandler] Mensagem de cálculo recebida (bruta): " + receivedLine);
            try {
                // 1. Decodificar e Verificar Segurança
                String[] parts = receivedLine.split("::");
                if (parts.length != 2) throw new SecurityException("Formato inválido.");
                byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
                byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

                // 2. Verificar HMAC
                boolean isHmacValid = SecurityUtils.checkHmac(this.sharedKey, encryptedData, receivedHmac);
                if (!isHmacValid) throw new SecurityException("HMAC inválido.");
                System.out.println("[CalcHandler] HMAC verificado.");

                // 3. Decifrar
                byte[] decryptedData = SecurityUtils.decrypt(this.sharedKey, encryptedData);
                String command = new String(decryptedData, StandardCharsets.UTF_8);
                System.out.println("[CalcHandler] Comando decifrado: " + command);

                // 4. Processar o cálculo
                String response = calculate(command);

                // 5. Enviar resposta segura
                sendSecureMessage(out, response, this.sharedKey);

            } catch (Exception e) {
                System.err.println("[CalcHandler] Erro de segurança ou cálculo: " + e.getMessage());
            }
        } catch (Exception e) {
            // Silencioso
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    private String calculate(String command) {
        String[] parts = command.split(" ");
        if (parts.length < 3) return "ERROR;Formato inválido. Use: <OPERACAO> <n1> <n2>";

        try {
            String operation = parts[0].toUpperCase();
            double n1 = Double.parseDouble(parts[1]);
            double n2 = Double.parseDouble(parts[2]);
            double result;

            switch (operation) {
                case "SOMA": result = n1 + n2; break;
                case "SUBTRACAO": result = n1 - n2; break;
                case "MULTIPLICACAO": result = n1 * n2; break;
                case "DIVISAO":
                    if (n2 == 0) return "ERROR;Divisão por zero.";
                    result = n1 / n2;
                    break;
                default:
                    return "ERROR;Operação desconhecida: " + operation;
            }
            return "OK;Resultado: " + result;
        } catch (NumberFormatException e) {
            return "ERROR;Números inválidos.";
        }
    }

    private void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }
}