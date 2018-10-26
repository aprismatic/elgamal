namespace Aprismatic.ElGamalExt
{
    public abstract class ElGamalAbstractCipher
    {
        protected readonly int CiphertextBlocksize;
        protected ElGamalKeyStruct KeyStruct;

        public ElGamalAbstractCipher(ElGamalKeyStruct p_key_struct)
        {
            KeyStruct = p_key_struct;
            CiphertextBlocksize = p_key_struct.getCiphertextBlocksize();
        }
    }
}
