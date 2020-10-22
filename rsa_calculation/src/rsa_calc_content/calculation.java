package rsa_calc_content;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * written by @author ZyzonixDev
 * published by ZyzonixDevelopments
 * -
 * date    | 13/10/2020
 * java-v  | 14
 * -
 * project | rsa_calculation
 * package | rsa_calc_content
 */

//N: 1457 E: 67 D: 103
//N: 391 E: 67 D: 331 / p1: 17 p2: 23

public class calculation {
    static boolean primecheckpassed = false;
    static boolean numberisprime = true;
    static boolean e_generatingpassed = false;
    static HashMap<Integer, Integer> pubkey = new HashMap<>();
    static HashMap<Integer, Integer> privkey = new HashMap<>();

    public static void main (String [] args) throws IOException {
        System.out.println("starting...");
        runner();
    }

    static void runner() throws IOException {
        //requesting action, starting action
        int action_result = action();
        if (action_result == 0) {
            System.out.println("shutting down...");
            System.exit(0);
        } else if (action_result == 1) {
            checking();
        } else if (action_result == 2) {
            cracking();
        } else if (action_result == 3) {
            calculation();
        }
    }

    //checking RSA-Encryption
    static void checking() throws IOException {
        try {
            test(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("\nReturning to beginning... \n");
        runner();
    }
    //calculating new RSA keys
    static void calculation() throws IOException {
        BigInteger[] numberarray = new BigInteger[2];
        BigInteger N = new BigInteger("0");
        BigInteger M = new BigInteger("0");
        BigInteger[] publickey = new BigInteger[2];
        BigInteger[] privatekey = new BigInteger[2];
        try {
            numberarray = numbInp();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        if (primecheckpassed == false) {
            System.out.println("\nplease retry and pick other numbers!");
            return;
        }
        //generating N and M (required for priv-key)
        N = numberarray[0].multiply(numberarray[1]);
        M = (numberarray[0].subtract(BigInteger.ONE).multiply(numberarray[1].subtract(BigInteger.ONE)));
        publickey[0] = N;
        //prooving that E matches the requirements
        try {
            publickey[1] = e_gen(M); // <-- generation number e; ggT[e;m] = 1 && 1<e<M
            System.out.println("----------\npublickey calculated successfully \n----------\n");
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        //if E doesn't match the requirements
        if (e_generatingpassed == false) {
            if (numberarray[0].compareTo(BigInteger.TWO) == -1 || numberarray[1].compareTo(BigInteger.TWO) == -1) {
                System.out.println("\nthe given number may match the requirements... \n\nbut: '" + numberarray[0] + "' and '" + numberarray[1] + "' aren't valid parameters!");
            } else {
                System.out.println("\nthe given number doesn't match the requirements! \n\nbut: '" + numberarray[0] + "' and '" + numberarray[1] + "' are valid parameters!");
            }
            return;
        }
        //calculating private key
        try {
            privatekey[1] = eukldalgh(publickey[1], M);
            if (privatekey[1] != null){
                System.out.println("----------\nprivatekey calculated successfully! \n----------\n");
            } else {
                System.out.println("something went wrong, please check your numbers!");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        //checking if E =/= D and D > 0
        try {
            BigInteger check_result = check(publickey[1], privatekey[1], M);
            if (check_result == null) {
                System.out.println("something went wrong, please check your numbers!");
                return;
            } else {
                privatekey[1] = check_result;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        //conclusion of results
        sumup(publickey[1], privatekey[1], publickey[0]);
        System.out.println("\nReturning to beginning... \n");
        runner();
    }
    //cracking RSA encryption
    static void cracking() throws IOException {
        BufferedReader read =  new BufferedReader(new InputStreamReader(System.in));
        System.out.println("please type in your public key, starting with N: (N + E)");
        BigInteger N = new BigInteger(read.readLine());
        System.out.println("E:");
        BigInteger E = new BigInteger(read.readLine());
        BigInteger[] primefact = primefact(N, E);
        if (!primefact[0].multiply(primefact[1]).equals(N)) {
            System.out.println("something has gone wrong, please retry...");
            return;
        }
        BigInteger M = primefact[0].subtract(BigInteger.ONE).multiply(primefact[1].subtract(BigInteger.ONE));
        BigInteger D = eukldalgh(E, M);
        if (D.compareTo(BigInteger.ONE) == -1) {
            D = D.add(M);
        }
        sumup(E, D, N);
        System.out.println("\nReturning to beginning... \n");
        runner();
    }

    //requesting action
    static int action() throws IOException {
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("\nWhat do you want to do?\n[t] testing RSA encryption / [g] generate keys / [c] crack RSA-encrytion \n");
        String answ = read.readLine().toLowerCase();
        if (answ.equals("t") || answ.equals("g") || answ.equals("c")) {
            if (answ.equals("t")) {
                return 1;
            } else if (answ.equals("c")){
                return 2;
            } else {
                return 3;
            }
        } else {
            return 0;
        }
    }

    //getting user input for key calculation
    static BigInteger[] numbInp() throws IOException {
        BigInteger[] result = new BigInteger[2];
        result[0] = BigInteger.valueOf(0);
        result[1] = BigInteger.valueOf(0);
        String inta_inp;
        String intb_inp;
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("\nenter your first primenumber:");
        inta_inp = read.readLine();
        System.out.println("enter your second primenumber:");
        intb_inp = read.readLine();
        System.out.println("\n");

        BigInteger a_str_to_int = new BigInteger(inta_inp);
        BigInteger b_str_to_int = new BigInteger(intb_inp);
        if ((a_str_to_int.compareTo(BigInteger.valueOf(1)) == -1) || (b_str_to_int.compareTo(BigInteger.valueOf(1)) == -1) || a_str_to_int.equals(1) || a_str_to_int.equals(1)) {
            System.out.println("your numbers are too small, there are only numbers above 1 allowed");
            return result;
        }

        if (a_str_to_int == b_str_to_int) {
            System.out.println(a_str_to_int + "=" +  b_str_to_int);
            return result;
        }
        BigInteger primea = primecheck(a_str_to_int);
        primecheckres(primea);
        BigInteger primeb = primecheck(b_str_to_int);
        primecheckres(primeb);
        if (primea.equals(0) || primeb.equals(0)) return result; else primecheckpassed = true; result[0] = primea; result[1] = primeb; return result;
    }
    //checking if number is primenumber
    static BigInteger primecheck(BigInteger numb) {
        //primenumberckeck of first value
        BigInteger primenumb = numb;
        if (numb.equals(0) || numb.compareTo(BigInteger.valueOf(1)) == -1 || BigInteger.valueOf(2).multiply(numb.divide(BigInteger.valueOf(2))).equals(numb)) {
            numberisprime = false;
            primenumb = BigInteger.ZERO;
        }
        BigInteger check;
        if (numberisprime = true) {
            for (BigInteger looper = numb.subtract(BigInteger.valueOf(1)); looper.compareTo(BigInteger.valueOf(1)) == 1; looper = looper.subtract(BigInteger.ONE)) {
                check = numb.divide(looper);
                if (check.multiply(looper).equals(numb)) {
                    numberisprime = false;
                    primenumb = BigInteger.ZERO;
                }
            }
        }
        return primenumb;
    }
    //confirming to console
    static BigInteger primecheckres(BigInteger numb) {
        if (numberisprime == true) {
            System.out.println("----------\n'" + numb + "' is a valid primenumber \n----------\n");
            return numb;
        } else {
            System.out.println("---------- \n'" + numb + "' is not a valid value \n----------\n");
            return BigInteger.ZERO;
        }
    }
    //checking if E matches the requirements
    static BigInteger e_gen(BigInteger M) throws IOException {
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("please select a number for your publickey (primenumbers are helpful..):");
        String pubkey_e = read.readLine();
        BigInteger e_in_int = new BigInteger(pubkey_e);
        if ((e_in_int.compareTo(BigInteger.TWO) == -1) || (e_in_int.compareTo(M) == 1)) {
            System.out.println(e_in_int + " is not a valid parameter, select another one");
            e_generatingpassed = false;
            return e_in_int;
        }
        for (BigInteger efcalc = e_in_int; efcalc.compareTo(BigInteger.ONE) == 1; efcalc = efcalc.subtract(BigInteger.ONE)) {
            BigInteger calcone = e_in_int.divide(efcalc);
            BigInteger calctwo = M.divide(efcalc);
            if (calcone.multiply(efcalc).equals(e_in_int) && calctwo.multiply(efcalc).equals(M)) {
                System.out.println("\n'" + e_in_int + "' doesn't match the requirements! \n");
                e_generatingpassed = false;
                return e_in_int;
            }
        }
        System.out.println("----------\nsuccess! '" + e_in_int + "' can be used for your publickey\n---------- \n");
        e_generatingpassed = true;
        return e_in_int;
    }
    //next two: modulo calculation, first returns mod, second count
    static BigInteger modcalc(BigInteger e, BigInteger m) {
        BigInteger e_through_m = e.divide(m);
        BigInteger e_mod_m = e.subtract(m.multiply(e_through_m));
        return e_mod_m;
    }
    static BigInteger modcalc_res(BigInteger e, BigInteger m) { //zweimal da wg. return
        BigInteger e_through_m = e.divide(m);
        return e_through_m;
    }
    //extended euclidean algorithm
    static BigInteger eukldalgh(BigInteger e_e, BigInteger e_m) {
        boolean euklone_finished = false;
        BigInteger use_e = e_e;
        BigInteger use_m = e_m;
        BigInteger mod_result;
        BigInteger modcalc_result;
        int back_count = 0;
        ArrayList<BigInteger> backstep = new ArrayList<BigInteger>();
        for (;!euklone_finished;) {
            mod_result = modcalc(use_e, use_m);
            modcalc_result = modcalc_res(use_e, use_m);
            backstep.add(modcalc_result);

            use_e = use_m;
            use_m = mod_result;

            if (mod_result.equals(BigInteger.ZERO)) {
                euklone_finished = true;
            }
            back_count++;
        }

        BigInteger a = BigInteger.ZERO;
        BigInteger b;
        BigInteger b_old = BigInteger.ONE;
        backstep.remove(backstep.size() - 1);
        for (; back_count > 1; back_count--) {
            b = (a).subtract((b_old).multiply(backstep.get(backstep.size() - 1)));
            a = b_old;
            b_old = b;
            backstep.remove(backstep.size() - 1);
        }
        return a;
    }
    //checking if E and D are matching the requirements
    static BigInteger check(BigInteger check_e, BigInteger check_d, BigInteger M) {
        BigInteger check_result = check_d;
        boolean checkpassed = false;
        if (check_e != check_d) {
            checkpassed = true;
        }
        if (check_d.compareTo(BigInteger.ZERO) == -1) {
            check_result = check_d.add(M);
            System.out.println(M);
            System.out.println(check_result);
            System.out.println(check_d);
        }
        if (checkpassed != true) {
            check_result = BigInteger.ZERO;
        }
        return check_result;
    }
    static void test(BigInteger publickey, BigInteger privatekey, BigInteger mod_numb) throws IOException {
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        BigInteger t_N = mod_numb;
        BigInteger t_pubk = publickey;
        BigInteger t_prik = privatekey;
        BigInteger encrypt_result;
        BigInteger decrypt_result;
        BigInteger encrypt_numb;

        if (t_pubk.equals(BigInteger.ZERO) || t_prik.equals(BigInteger.ZERO) || t_N.equals(BigInteger.ZERO)) {
            System.out.println("\nyour publickey (N):");
            String t_t_N = read.readLine();
            System.out.println("your publickey (E):");
            String t_t_E = read.readLine();
            System.out.println("your privatekey (D):");
            String t_t_D = read.readLine();
            t_N = new BigInteger(t_t_N);
            t_pubk = new BigInteger(t_t_E);
            t_prik = new BigInteger(t_t_D);
        }
        System.out.println("\nstarting encryption: \nnumber for en-/ and decryption:");
        encrypt_numb = new BigInteger(read.readLine());
        encrypt_result = dencrypt(encrypt_numb,t_pubk, t_N);
        System.out.println("\n----------\nyour encrypted number: '" + encrypt_result + "'\n----------\n");

        System.out.println("\nstarting decryption: \ndecrypted code: '" + encrypt_result + "'");
        decrypt_result = dencrypt(encrypt_result, t_prik, t_N);
        System.out.println("\n----------\nyour encrypted number: '" + decrypt_result + "'\n----------\n");

        BigInteger n1 = decrypt_result;
        BigInteger n2 = encrypt_numb;
        if (n1.equals(n2)) {
            System.out.println("\n\n----------------------------------------------------------------\nTEST PASSED, your keys are working! \n----------------------------------------------------------------");
        } else {
            System.out.println("something went wrong");
        }
    }
    // BASE^privkey/pubkey mod N
    static BigInteger dencrypt(BigInteger BASE, BigInteger exp, BigInteger N){
        BigInteger result;
        int expo = exp.intValue();
        result = BASE.pow(expo).remainder(N);
        return result;
    }
    //prime factorization
    static BigInteger[] primefact(BigInteger N, BigInteger E) throws IOException{
        BigInteger[] primefact_result = new BigInteger[2];
        BigInteger pre_looper = N;
        BigInteger looper;
        boolean primeres;
        if (pre_looper.divide(BigInteger.TWO).multiply(BigInteger.TWO).equals(pre_looper)) {
            looper = pre_looper.subtract(BigInteger.ONE);
        } else {
            looper = pre_looper;
        }
        for (; looper.compareTo(BigInteger.ONE) == 1; looper = looper.subtract(BigInteger.TWO)) {
            if (!(looper.toString().endsWith("5") || looper.divide(BigInteger.TWO).multiply(BigInteger.TWO).equals(looper))) {
                if (primecheckret(looper) == true) {
                    BigInteger a;
                    BigInteger b;
                    a = looper;
                    b = N.divide(looper);
                    if ((primecheckret(N.divide(looper)) == true) && a.multiply(b).equals(N)) {
                        primefact_result[0] = a;
                        primefact_result[1] = b;
                        return primefact_result;
                    }
                }
            }
        }
        return primefact_result;
    }
    static boolean primecheckret(BigInteger numb) {
        if (primecheck(numb).equals(numb)) {
            return true;
        }
        return false;
    }
    static void sumup(BigInteger publickey, BigInteger privatekey, BigInteger N) throws IOException {
        System.out.println("\n-----------------------------------------------");
        System.out.println("publickey:\nN: " + N + "\nE: " + publickey + "\n");
        System.out.println("privatekey:\nN: " + N + "\nD: " + privatekey);
        System.out.println("-----------------------------------------------");
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("\ndo you want to test your public & privatekey? [y/n]");
        String answ = read.readLine();
        answ.toLowerCase();
        if (answ.equals("n")) {
            System.out.println("\nshutting down...");
            return;
        } else if (answ.equals("y")) {
            test(publickey, privatekey, N);
        }
    }
}
